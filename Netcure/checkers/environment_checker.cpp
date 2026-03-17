#include "pch.h"
#include "environment_checker.h"

#include <Windows.h>
#include <winternl.h>
#include <Iphlpapi.h>

#include <algorithm>
#include <format>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

namespace netcure::checkers {
	namespace {
		struct os_version_info {
			DWORD major = 0;
			DWORD minor = 0;
			DWORD build = 0;
		};

		using rtl_get_version_fn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);

		std::string read_registry_string(const HKEY root, const wchar_t* sub_key, const wchar_t* value_name) {
			DWORD type = 0;
			DWORD size = 0;
			const auto query_size_rc = RegGetValueW(root, sub_key, value_name, RRF_RT_REG_SZ, &type, nullptr, &size);
			if (query_size_rc != ERROR_SUCCESS || size < sizeof(wchar_t)) {
				return "";
			}

			std::wstring value(size / sizeof(wchar_t), L'\0');
			const auto query_value_rc = RegGetValueW(root, sub_key, value_name, RRF_RT_REG_SZ, &type, value.data(), &size);
			if (query_value_rc != ERROR_SUCCESS) {
				return "";
			}

			value.resize((size / sizeof(wchar_t)) > 0 ? (size / sizeof(wchar_t)) - 1 : 0);
			return utils::to_string(value);
		}

		std::optional<DWORD> read_registry_dword(const HKEY root, const wchar_t* sub_key, const wchar_t* value_name) {
			DWORD type = 0;
			DWORD value = 0;
			DWORD size = sizeof(value);
			const auto rc = RegGetValueW(root, sub_key, value_name, RRF_RT_REG_DWORD, &type, &value, &size);
			if (rc != ERROR_SUCCESS) {
				return std::nullopt;
			}

			return value;
		}

		std::string get_computer_name() {
			DWORD size = 0;
			GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);
			if (size == 0) {
				return "";
			}

			std::wstring name(size, L'\0');
			if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, name.data(), &size)) {
				return "";
			}

			name.resize(size);
			return utils::to_string(name);
		}

		std::string get_architecture() {
			SYSTEM_INFO system_info{};
			GetNativeSystemInfo(&system_info);
			switch (system_info.wProcessorArchitecture) {
			case PROCESSOR_ARCHITECTURE_AMD64:
				return "x64";
			case PROCESSOR_ARCHITECTURE_ARM64:
				return "ARM64";
			case PROCESSOR_ARCHITECTURE_INTEL:
				return "x86";
			default:
				return "unknown";
			}
		}

		std::optional<os_version_info> get_os_version_info() {
			const auto ntdll = GetModuleHandleW(L"ntdll.dll");
			if (ntdll == nullptr) {
				return std::nullopt;
			}

			const auto rtl_get_version = reinterpret_cast<rtl_get_version_fn>(GetProcAddress(ntdll, "RtlGetVersion"));
			if (rtl_get_version == nullptr) {
				return std::nullopt;
			}

			RTL_OSVERSIONINFOW info{};
			info.dwOSVersionInfoSize = sizeof(info);
			if (rtl_get_version(&info) != 0) {
				return std::nullopt;
			}

			return os_version_info{
				.major = info.dwMajorVersion,
				.minor = info.dwMinorVersion,
				.build = info.dwBuildNumber
			};
		}

		std::string get_os_version_text(const std::optional<os_version_info>& version_info) {
			if (!version_info.has_value()) {
				return "";
			}

			return std::format("{}.{}.{}", version_info->major, version_info->minor, version_info->build);
		}

		std::string normalize_windows_product_name(std::string product_name, const std::optional<os_version_info>& version_info) {
			constexpr std::string_view windows_10_prefix = "Windows 10";
			if (!version_info.has_value()) {
				return product_name;
			}

			// Windows 11 still reports itself as NT 10.0, but client builds start at 22000.
			if (version_info->major == 10 &&
				version_info->build >= 22000 &&
				product_name.rfind(windows_10_prefix, 0) == 0) {
				product_name.replace(0, windows_10_prefix.size(), "Windows 11");
			}

			return product_name;
		}

		std::vector<std::string> get_network_adapter_models() {
			struct adapter_addresses_deleter {
				void operator()(IP_ADAPTER_ADDRESSES* ptr) const {
					delete[] reinterpret_cast<char*>(ptr);
				}
			};

			std::vector<std::string> models;
			ULONG buffer_length = 0x4000;
			for (int attempt = 0; attempt < 3; ++attempt) {
				std::unique_ptr<IP_ADAPTER_ADDRESSES, adapter_addresses_deleter> addresses(
					reinterpret_cast<IP_ADAPTER_ADDRESSES*>(new char[buffer_length])
				);

				const auto rc = GetAdaptersAddresses(
					AF_UNSPEC,
					GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
					nullptr,
					addresses.get(),
					&buffer_length
				);
				if (rc == ERROR_BUFFER_OVERFLOW) {
					continue;
				}

				if (rc != NO_ERROR) {
					return models;
				}

				for (const auto* current = addresses.get(); current != nullptr; current = current->Next) {
					if (current->Description == nullptr || current->Description[0] == L'\0') {
						continue;
					}

					models.emplace_back(utils::to_string(std::wstring(current->Description)));
				}

				std::ranges::sort(models);
				models.erase(std::unique(models.begin(), models.end()), models.end());
				return models;
			}

			return models;
		}
	}

	void environment_checker::run(checker_context& ctx) {
		auto& report = ctx.result.host_environment;
		const auto os_version_info = get_os_version_info();

		report.computer_name = get_computer_name();
		report.system_manufacturer = read_registry_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
		report.system_model = read_registry_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
		report.os_name = normalize_windows_product_name(
			read_registry_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName"),
			os_version_info
		);
		report.os_version = get_os_version_text(os_version_info);
		report.os_build = read_registry_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuildNumber");
		report.os_display_version = read_registry_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"DisplayVersion");
		if (report.os_display_version.empty()) {
			report.os_display_version = read_registry_string(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId");
		}

		if (const auto ubr = read_registry_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR"); ubr.has_value()) {
			if (!report.os_build.empty()) {
				report.os_build = std::format("{}.{}", report.os_build, *ubr);
			}
		}

		report.architecture = get_architecture();
		report.network_adapter_models = get_network_adapter_models();
	}
}
