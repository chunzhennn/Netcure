#include "pch.h"
#include "checker.h"
#include "adapter_checker.h"
#include "../utils.h"
#include <string>
#include <format>
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <utility>

#include <WinSock2.h>
#include <Iphlpapi.h>
#include <ws2tcpip.h>

namespace netcure::checkers {
	namespace {
		auto _get_adapter_addresses() {
			struct adapter_addresses_deleter {
				void operator()(IP_ADAPTER_ADDRESSES* ptr) const {
					delete[] reinterpret_cast<char*>(ptr);
				}
			};
			IP_ADAPTER_ADDRESSES* addresses = nullptr;
			ULONG buflen = 0x4000;
			for (int i = 0; i < 3; i++) { // 3 tries max
				addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(new char[buflen]);
				auto rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, addresses, &buflen);
				if (rc == NO_ERROR) {
					return std::unique_ptr<IP_ADAPTER_ADDRESSES, adapter_addresses_deleter>(addresses);
				}
				else if (rc == ERROR_BUFFER_OVERFLOW) {
					delete[] addresses;
					addresses = nullptr;
				}
				else if (rc == ERROR_NO_DATA) {
					delete[] addresses;
					throw std::runtime_error("No enabled network adapters found");
				}
				else {
					delete[] addresses;
					throw std::runtime_error(std::format("GetAdaptersAddresses failed with error code: {}", rc));
				}
			}
			throw std::runtime_error("Failed to allocate memory for GetAdaptersAddresses");
		}
	}
	void adapter_checker::run(checker_context& ctx) {
		auto addresses = _get_adapter_addresses();

		for (const auto* current = addresses.get(); current; current = current->Next) {
			// We use friendly name instead of adapter name
			std::wstring adapter_name = current->FriendlyName ? current->FriendlyName : L"Unknown";
			std::vector<utils::cidr<utils::ipv4_addr>> ipv4_addresses;
			std::vector<utils::cidr<utils::ipv6_addr>> ipv6_addresses;
			std::vector<utils::ipv4_addr> dns4_addresses;
			std::vector<utils::ipv6_addr> dns6_addresses;
			std::vector<utils::ipv4_addr> gateway4_addresses;
			std::vector<utils::ipv6_addr> gateway6_addresses;

			char addr_buf[64] = { 0 };

			for (const auto* addr = current->FirstUnicastAddress; addr; addr = addr->Next) {
				// Note that we've done extra string conversion here
				// but it's necessary for compatibility with utils::ip_addr
				if (addr->Address.lpSockaddr->sa_family == AF_INET) {
					auto* v4addr = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
					auto* v4str = inet_ntop(AF_INET, &v4addr->sin_addr, addr_buf, sizeof(addr_buf));
					if (v4str == nullptr)
						continue;
					ipv4_addresses.emplace_back(utils::ipv4_addr{ v4str }, addr->OnLinkPrefixLength);
				} else if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
					auto* v6addr = reinterpret_cast<sockaddr_in6*>(addr->Address.lpSockaddr);
					auto* v6str = inet_ntop(AF_INET6, &v6addr->sin6_addr, addr_buf, sizeof(addr_buf));
					if (v6str == nullptr)
						continue;
					ipv6_addresses.emplace_back(utils::ipv6_addr{ v6str }, addr->OnLinkPrefixLength);
				}
			}
			
			for (const auto* addr = current->FirstGatewayAddress; addr; addr = addr->Next) {
				if (addr->Address.lpSockaddr->sa_family == AF_INET) {
					auto* v4addr = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
					auto* v4str = inet_ntop(AF_INET, &v4addr->sin_addr, addr_buf, sizeof(addr_buf));
					if (v4str == nullptr)
						continue;
					gateway4_addresses.emplace_back(v4str);
				}
				else if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
					auto* v6addr = reinterpret_cast<sockaddr_in6*>(addr->Address.lpSockaddr);
					auto* v6str = inet_ntop(AF_INET6, &v6addr->sin6_addr, addr_buf, sizeof(addr_buf));
					if (v6str == nullptr)
						continue;
					gateway6_addresses.emplace_back(v6str);
				}
			}

			for (const auto* addr = current->FirstDnsServerAddress; addr; addr = addr->Next) {
				if (addr->Address.lpSockaddr->sa_family == AF_INET) {
					auto* v4addr = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
					auto* v4str = inet_ntop(AF_INET, &v4addr->sin_addr, addr_buf, sizeof(addr_buf));
					if (v4str == nullptr)
						continue;
					dns4_addresses.emplace_back(v4str);
				} else if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
					auto* v6addr = reinterpret_cast<sockaddr_in6*>(addr->Address.lpSockaddr);
					auto* v6str = inet_ntop(AF_INET6, &v6addr->sin6_addr, addr_buf, sizeof(addr_buf));
					if (v6str == nullptr)
						continue;
					dns6_addresses.emplace_back(v6str);
				}
			}
			
			if (current->IfType == IF_TYPE_IEEE80211) {
				ctx.has_wireless_adapter = true;
			}

			ctx.result.network_interfaces.emplace_back(utils::network_interface{
				.id = current->Luid,
				.name = utils::to_string(adapter_name),
				.mac_address = utils::mac(std::string_view(reinterpret_cast<const char*>(&current->PhysicalAddress), current->PhysicalAddressLength)),
				.up = (current->OperStatus == IfOperStatusUp),
				.ipv4_addresses = std::move(ipv4_addresses),
				.gateway4_addresses = std::move(gateway4_addresses),
				.dns4_addresses = std::move(dns4_addresses),
				.ipv6_addresses = std::move(ipv6_addresses),
				.gateway6_addresses = std::move(gateway6_addresses),
				.dns6_addresses = std::move(dns6_addresses)
			});
		}
	}

}