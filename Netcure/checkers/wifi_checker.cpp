#include "pch.h"
#include "wifi_checker.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <Iphlpapi.h>
#include <wlanapi.h>
#include <windot11.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")

namespace netcure::checkers {
	namespace {
		constexpr auto wlan_scan_wait_timeout = std::chrono::seconds(10);

		struct wlan_handle_deleter {
			void operator()(HANDLE handle) const {
				if (handle != nullptr) {
					WlanCloseHandle(handle, nullptr);
				}
			}
		};

		template<typename T>
		struct wlan_memory_deleter {
			void operator()(T* ptr) const {
				if (ptr != nullptr) {
					WlanFreeMemory(ptr);
				}
			}
		};

		using unique_wlan_handle = std::unique_ptr<void, wlan_handle_deleter>;

		template<typename T>
		using unique_wlan_memory = std::unique_ptr<T, wlan_memory_deleter<T>>;

		struct available_network_snapshot {
			std::string profile_name;
			std::string auth_algorithm;
			std::string cipher_algorithm;
			bool security_enabled = false;
			bool connectable = false;
		};

		struct scan_wait_context {
			GUID interface_guid{};
			std::mutex mutex;
			std::condition_variable condition;
			bool completed = false;
			DWORD result = ERROR_TIMEOUT;
		};

		struct scan_result {
			bool requested = false;
			bool completed = false;
		};

		bool _guid_equal(const GUID& lhs, const GUID& rhs) {
			return std::memcmp(&lhs, &rhs, sizeof(GUID)) == 0;
		}

		bool _same_luid(const if_id_type& lhs, const if_id_type& rhs) {
			return std::memcmp(&lhs, &rhs, sizeof(if_id_type)) == 0;
		}

		std::string _wide_to_string(const wchar_t* value) {
			return utils::to_string(std::wstring(value != nullptr ? value : L""));
		}

		std::string _ssid_to_string(const DOT11_SSID& ssid) {
			if (ssid.uSSIDLength == 0) {
				return "<hidden>";
			}

			std::string result;
			result.reserve(ssid.uSSIDLength);
			for (ULONG i = 0; i < ssid.uSSIDLength; ++i) {
				const auto ch = static_cast<char>(ssid.ucSSID[i]);
				if (std::isprint(static_cast<unsigned char>(ch)) != 0) {
					result.push_back(ch);
				} else {
					return std::format("<non-printable:{} bytes>", ssid.uSSIDLength);
				}
			}
			return result;
		}

		utils::mac _to_mac(const BYTE* bytes, size_t length) {
			return utils::mac(std::string_view(reinterpret_cast<const char*>(bytes), length));
		}

		std::string _interface_state_to_string(const WLAN_INTERFACE_STATE state) {
			switch (state) {
			case wlan_interface_state_not_ready:
				return "not_ready";
			case wlan_interface_state_connected:
				return "connected";
			case wlan_interface_state_ad_hoc_network_formed:
				return "ad_hoc_network_formed";
			case wlan_interface_state_disconnecting:
				return "disconnecting";
			case wlan_interface_state_disconnected:
				return "disconnected";
			case wlan_interface_state_associating:
				return "associating";
			case wlan_interface_state_discovering:
				return "discovering";
			case wlan_interface_state_authenticating:
				return "authenticating";
			default:
				return "unknown";
			}
		}

		std::string _bss_type_to_string(const DOT11_BSS_TYPE type) {
			switch (type) {
			case dot11_BSS_type_infrastructure:
				return "infrastructure";
			case dot11_BSS_type_independent:
				return "ad_hoc";
			case dot11_BSS_type_any:
				return "any";
			default:
				return "unknown";
			}
		}

		std::string _phy_type_to_string(const DOT11_PHY_TYPE type) {
			switch (type) {
			case dot11_phy_type_fhss:
				return "FHSS";
			case dot11_phy_type_dsss:
				return "DSSS";
			case dot11_phy_type_irbaseband:
				return "IR";
			case dot11_phy_type_ofdm:
				return "OFDM";
			case dot11_phy_type_hrdsss:
				return "HR-DSSS";
			case dot11_phy_type_erp:
				return "ERP";
			case dot11_phy_type_ht:
				return "802.11n/HT";
			case dot11_phy_type_vht:
				return "802.11ac/VHT";
			case dot11_phy_type_dmg:
				return "802.11ad/DMG";
#ifdef dot11_phy_type_he
			case dot11_phy_type_he:
				return "802.11ax/HE";
#endif
#ifdef dot11_phy_type_eht
			case dot11_phy_type_eht:
				return "802.11be/EHT";
#endif
			default:
				return "unknown";
			}
		}

		std::string _auth_algorithm_to_string(const DOT11_AUTH_ALGORITHM algorithm) {
			switch (algorithm) {
			case DOT11_AUTH_ALGO_80211_OPEN:
				return "Open";
			case DOT11_AUTH_ALGO_80211_SHARED_KEY:
				return "Shared Key";
			case DOT11_AUTH_ALGO_WPA:
				return "WPA-Enterprise";
			case DOT11_AUTH_ALGO_WPA_PSK:
				return "WPA-Personal";
			case DOT11_AUTH_ALGO_WPA_NONE:
				return "WPA-None";
			case DOT11_AUTH_ALGO_RSNA:
				return "WPA2/WPA3-Enterprise";
			case DOT11_AUTH_ALGO_RSNA_PSK:
				return "WPA2/WPA3-Personal";
#ifdef DOT11_AUTH_ALGO_WPA3
			case DOT11_AUTH_ALGO_WPA3:
				return "WPA3-Enterprise";
#endif
#ifdef DOT11_AUTH_ALGO_WPA3_SAE
			case DOT11_AUTH_ALGO_WPA3_SAE:
				return "WPA3-SAE";
#endif
#ifdef DOT11_AUTH_ALGO_OWE
			case DOT11_AUTH_ALGO_OWE:
				return "OWE";
#endif
			default:
				return "unknown";
			}
		}

		std::string _cipher_algorithm_to_string(const DOT11_CIPHER_ALGORITHM algorithm) {
			switch (algorithm) {
			case DOT11_CIPHER_ALGO_NONE:
				return "None";
			case DOT11_CIPHER_ALGO_WEP40:
				return "WEP40";
			case DOT11_CIPHER_ALGO_TKIP:
				return "TKIP";
			case DOT11_CIPHER_ALGO_CCMP:
				return "CCMP/AES";
			case DOT11_CIPHER_ALGO_WEP104:
				return "WEP104";
			case DOT11_CIPHER_ALGO_WEP:
				return "WEP";
#ifdef DOT11_CIPHER_ALGO_GCMP
			case DOT11_CIPHER_ALGO_GCMP:
				return "GCMP";
#endif
#ifdef DOT11_CIPHER_ALGO_GCMP_256
			case DOT11_CIPHER_ALGO_GCMP_256:
				return "GCMP-256";
#endif
#ifdef DOT11_CIPHER_ALGO_CCMP_256
			case DOT11_CIPHER_ALGO_CCMP_256:
				return "CCMP-256";
#endif
			case DOT11_CIPHER_ALGO_BIP:
				return "BIP";
#ifdef DOT11_CIPHER_ALGO_BIP_GMAC_128
			case DOT11_CIPHER_ALGO_BIP_GMAC_128:
				return "BIP-GMAC-128";
#endif
#ifdef DOT11_CIPHER_ALGO_BIP_GMAC_256
			case DOT11_CIPHER_ALGO_BIP_GMAC_256:
				return "BIP-GMAC-256";
#endif
#ifdef DOT11_CIPHER_ALGO_BIP_CMAC_256
			case DOT11_CIPHER_ALGO_BIP_CMAC_256:
				return "BIP-CMAC-256";
#endif
			default:
				return "unknown";
			}
		}

		std::optional<uint32_t> _frequency_to_channel(const uint32_t frequency_mhz) {
			if (frequency_mhz == 2484) {
				return 14;
			}
			if (frequency_mhz >= 2412 && frequency_mhz <= 2472) {
				return (frequency_mhz - 2407) / 5;
			}
			if (frequency_mhz >= 5000 && frequency_mhz <= 5895) {
				return (frequency_mhz - 5000) / 5;
			}
			if (frequency_mhz >= 5955 && frequency_mhz <= 7115) {
				return (frequency_mhz - 5950) / 5;
			}
			return std::nullopt;
		}

		std::string _band_from_frequency(const uint32_t frequency_mhz) {
			if (frequency_mhz >= 2400 && frequency_mhz < 2500) {
				return "2.4 GHz";
			}
			if (frequency_mhz >= 5000 && frequency_mhz < 5900) {
				return "5 GHz";
			}
			if (frequency_mhz >= 5925 && frequency_mhz < 7125) {
				return "6 GHz";
			}
			return "unknown";
		}

		std::optional<uint32_t> _parse_channel_width_mhz(const WLAN_BSS_ENTRY& entry) {
			if (entry.ulIeSize == 0) {
				return std::nullopt;
			}

			const auto* ie_bytes = reinterpret_cast<const BYTE*>(std::addressof(entry)) + entry.ulIeOffset;
			size_t offset = 0;
			std::optional<uint32_t> width_mhz;

			while (offset + 2 <= entry.ulIeSize) {
				const auto element_id = ie_bytes[offset];
				const auto element_size = ie_bytes[offset + 1];
				offset += 2;
				if (offset + element_size > entry.ulIeSize) {
					break;
				}

				const auto* body = ie_bytes + offset;
				switch (element_id) {
				case 61:
					if (element_size >= 2) {
						const auto ht_info_subset_1 = body[1];
						const auto secondary_offset = ht_info_subset_1 & 0x3;
						const auto forty_mhz_enabled = (ht_info_subset_1 & 0x4) != 0;
						width_mhz = (forty_mhz_enabled && secondary_offset != 0) ? 40u : 20u;
					}
					break;
				case 192:
					if (element_size >= 1) {
						switch (body[0]) {
						case 0:
							width_mhz = (std::max)(width_mhz.value_or(20u), 40u);
							break;
						case 1:
							width_mhz = 80u;
							break;
						case 2:
						case 3:
							width_mhz = 160u;
							break;
						default:
							break;
						}
					}
					break;
				default:
					break;
				}

				offset += element_size;
			}

			return width_mhz;
		}

		void WINAPI _scan_notification_callback(PWLAN_NOTIFICATION_DATA data, PVOID context) {
			if (data == nullptr || context == nullptr) {
				return;
			}

			auto* wait_context = static_cast<scan_wait_context*>(context);
			if (!_guid_equal(data->InterfaceGuid, wait_context->interface_guid)) {
				return;
			}

			if (data->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) {
				return;
			}

			std::scoped_lock lock(wait_context->mutex);
			switch (data->NotificationCode) {
			case wlan_notification_acm_scan_complete:
				wait_context->completed = true;
				wait_context->result = ERROR_SUCCESS;
				wait_context->condition.notify_all();
				break;
			case wlan_notification_acm_scan_fail:
				wait_context->completed = true;
				wait_context->result = data->dwDataSize >= sizeof(DWORD)
					? *static_cast<const DWORD*>(data->pData)
					: ERROR_GEN_FAILURE;
				wait_context->condition.notify_all();
				break;
			default:
				break;
			}
		}

		unique_wlan_handle _open_wlan_handle() {
			DWORD negotiated_version = 0;
			HANDLE raw_handle = nullptr;
			const auto rc = WlanOpenHandle(2, nullptr, &negotiated_version, &raw_handle);
			if (rc != ERROR_SUCCESS) {
				throw std::runtime_error(std::format("WlanOpenHandle failed with error code: {}", rc));
			}
			return unique_wlan_handle(raw_handle);
		}

		unique_wlan_memory<WLAN_INTERFACE_INFO_LIST> _enum_wlan_interfaces(HANDLE handle) {
			WLAN_INTERFACE_INFO_LIST* raw_interfaces = nullptr;
			const auto rc = WlanEnumInterfaces(handle, nullptr, &raw_interfaces);
			if (rc != ERROR_SUCCESS) {
				throw std::runtime_error(std::format("WlanEnumInterfaces failed with error code: {}", rc));
			}
			return unique_wlan_memory<WLAN_INTERFACE_INFO_LIST>(raw_interfaces);
		}

		template<typename T>
		std::optional<T> _query_interface_value(HANDLE handle, const GUID& interface_guid, const WLAN_INTF_OPCODE opcode) {
			DWORD data_size = 0;
			void* raw_data = nullptr;
			WLAN_OPCODE_VALUE_TYPE value_type = wlan_opcode_value_type_invalid;
			const auto rc = WlanQueryInterface(handle, &interface_guid, opcode, nullptr, &data_size, &raw_data, &value_type);
#ifdef ERROR_NDIS_DOT11_POWER_STATE_INVALID
			if (rc == ERROR_NOT_SUPPORTED || rc == ERROR_INVALID_STATE || rc == ERROR_NDIS_DOT11_POWER_STATE_INVALID) {
#else
			if (rc == ERROR_NOT_SUPPORTED || rc == ERROR_INVALID_STATE) {
#endif
				return std::nullopt;
			}
			if (rc != ERROR_SUCCESS) {
				throw std::runtime_error(std::format("WlanQueryInterface failed with error code: {}", rc));
			}

			unique_wlan_memory<std::byte> data(reinterpret_cast<std::byte*>(raw_data));
			if (data_size < sizeof(T)) {
				throw std::runtime_error("WlanQueryInterface returned insufficient data");
			}
			return *reinterpret_cast<const T*>(data.get());
		}

		unique_wlan_memory<WLAN_AVAILABLE_NETWORK_LIST> _get_available_networks(HANDLE handle, const GUID& interface_guid) {
			WLAN_AVAILABLE_NETWORK_LIST* raw_networks = nullptr;
			DWORD flags = WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES;
#ifdef WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES
			flags |= WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES;
#endif
			const auto rc = WlanGetAvailableNetworkList(handle, &interface_guid, flags, nullptr, &raw_networks);
			if (rc != ERROR_SUCCESS) {
				throw std::runtime_error(std::format("WlanGetAvailableNetworkList failed with error code: {}", rc));
			}
			return unique_wlan_memory<WLAN_AVAILABLE_NETWORK_LIST>(raw_networks);
		}

		unique_wlan_memory<WLAN_BSS_LIST> _get_bss_list(HANDLE handle, const GUID& interface_guid) {
			WLAN_BSS_LIST* raw_bss_list = nullptr;
			const auto rc = WlanGetNetworkBssList(handle, &interface_guid, nullptr, dot11_BSS_type_any, FALSE, nullptr, &raw_bss_list);
			if (rc != ERROR_SUCCESS) {
				throw std::runtime_error(std::format("WlanGetNetworkBssList failed with error code: {}", rc));
			}
			return unique_wlan_memory<WLAN_BSS_LIST>(raw_bss_list);
		}

		scan_result _perform_scan(HANDLE handle, const GUID& interface_guid) {
			scan_wait_context wait_context{};
			wait_context.interface_guid = interface_guid;

			const auto register_rc = WlanRegisterNotification(
				handle,
				WLAN_NOTIFICATION_SOURCE_ACM,
				FALSE,
				_scan_notification_callback,
				&wait_context,
				nullptr,
				nullptr
			);

			const auto scan_rc = WlanScan(handle, &interface_guid, nullptr, nullptr, nullptr);
			if (scan_rc != ERROR_SUCCESS) {
				if (register_rc == ERROR_SUCCESS) {
					WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, nullptr, nullptr, nullptr, nullptr);
				}
				return {};
			}

			if (register_rc != ERROR_SUCCESS) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1500));
				return { true, false };
			}

			std::unique_lock lock(wait_context.mutex);
			wait_context.condition.wait_for(lock, wlan_scan_wait_timeout, [&wait_context] {
				return wait_context.completed;
			});
			lock.unlock();

			WlanRegisterNotification(handle, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, nullptr, nullptr, nullptr, nullptr);
			return { true, wait_context.completed && wait_context.result == ERROR_SUCCESS };
		}

		std::string _resolve_interface_name(const checker_context& ctx, const if_id_type& interface_id, const std::string& fallback_name) {
			for (const auto& iface : ctx.result.network_interfaces) {
				if (_same_luid(iface.id, interface_id)) {
					return iface.name;
				}
			}
			return fallback_name;
		}

		std::optional<int32_t> _estimate_rssi_from_quality(const uint32_t signal_quality) {
			if (signal_quality > 100) {
				return std::nullopt;
			}
			return static_cast<int32_t>(signal_quality) / 2 - 100;
		}
	}

	bool wifi_checker::available(const checker_context& ctx) const {
		return ctx.has_wireless_adapter;
	}

	void wifi_checker::run(checker_context& ctx) {
		auto handle = _open_wlan_handle();
		auto interfaces = _enum_wlan_interfaces(handle.get());

		for (DWORD index = 0; index < interfaces->dwNumberOfItems; ++index) {
			const auto& info = interfaces->InterfaceInfo[index];
			if_id_type interface_id{};
			const auto convert_rc = ConvertInterfaceGuidToLuid(&info.InterfaceGuid, &interface_id);
			if (convert_rc != NO_ERROR) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::warning,
					.title = "Wi-Fi interface resolution failed",
					.description = std::format("Failed to convert WLAN interface GUID to LUID, error code: {}", convert_rc)
				});
				continue;
			}

			try {
				wifi_interface_report report{};
				report.interface_id = interface_id;
				report.description = _wide_to_string(info.strInterfaceDescription);
				report.interface_name = _resolve_interface_name(ctx, interface_id, report.description);
				report.connection.state = _interface_state_to_string(info.isState);

				const auto scan = _perform_scan(handle.get(), info.InterfaceGuid);
				report.scan_requested = scan.requested;
				report.scan_completed = scan.completed;

				auto available_networks = _get_available_networks(handle.get(), info.InterfaceGuid);
				std::unordered_map<std::string, available_network_snapshot> available_network_map;
				for (DWORD network_index = 0; network_index < available_networks->dwNumberOfItems; ++network_index) {
					const auto& network = available_networks->Network[network_index];
					available_network_map.insert_or_assign(
						_ssid_to_string(network.dot11Ssid),
						available_network_snapshot{
							.profile_name = _wide_to_string(network.strProfileName),
							.auth_algorithm = _auth_algorithm_to_string(network.dot11DefaultAuthAlgorithm),
							.cipher_algorithm = _cipher_algorithm_to_string(network.dot11DefaultCipherAlgorithm),
							.security_enabled = network.bSecurityEnabled != FALSE,
							.connectable = network.bNetworkConnectable != FALSE
						}
					);
				}

				const auto current_connection = _query_interface_value<WLAN_CONNECTION_ATTRIBUTES>(handle.get(), info.InterfaceGuid, wlan_intf_opcode_current_connection);
				const auto channel_number = _query_interface_value<DWORD>(handle.get(), info.InterfaceGuid, wlan_intf_opcode_channel_number);
				const auto rssi = _query_interface_value<LONG>(handle.get(), info.InterfaceGuid, wlan_intf_opcode_rssi);
				const auto radio_state = _query_interface_value<WLAN_RADIO_STATE>(handle.get(), info.InterfaceGuid, wlan_intf_opcode_radio_state);
				const auto statistics = _query_interface_value<WLAN_STATISTICS>(handle.get(), info.InterfaceGuid, wlan_intf_opcode_statistics);

				report.connection.radio_on = true;
				if (radio_state.has_value()) {
					report.connection.radio_on = false;
					for (DWORD phy_index = 0; phy_index < radio_state->dwNumberOfPhys; ++phy_index) {
						const auto& phy_state = radio_state->PhyRadioState[phy_index];
						if (phy_state.dot11HardwareRadioState == dot11_radio_state_on && phy_state.dot11SoftwareRadioState == dot11_radio_state_on) {
							report.connection.radio_on = true;
							break;
						}
					}
				}

				if (statistics.has_value()) {
					report.connection.unicast_tx_packets = statistics->MacUcastCounters.ullTransmittedFrameCount;
					report.connection.unicast_rx_packets = statistics->MacUcastCounters.ullReceivedFrameCount;
                  report.connection.failed_tx_packets = statistics->ullFourWayHandshakeFailures;
				}

				if (current_connection.has_value()) {
					const auto& association = current_connection->wlanAssociationAttributes;
					const auto& security = current_connection->wlanSecurityAttributes;
					report.connection.connected = current_connection->isState == wlan_interface_state_connected
						|| current_connection->isState == wlan_interface_state_ad_hoc_network_formed;
					report.connection.profile_name = _wide_to_string(current_connection->strProfileName);
					report.connection.ssid = _ssid_to_string(association.dot11Ssid);
					report.connection.bssid = _to_mac(association.dot11Bssid, sizeof(association.dot11Bssid));
					report.connection.phy_type = _phy_type_to_string(association.dot11PhyType);
					report.connection.bss_type = _bss_type_to_string(association.dot11BssType);
					report.connection.auth_algorithm = _auth_algorithm_to_string(security.dot11AuthAlgorithm);
					report.connection.cipher_algorithm = _cipher_algorithm_to_string(security.dot11CipherAlgorithm);
					report.connection.signal_quality = association.wlanSignalQuality;
					report.connection.rx_rate_kbps = association.ulRxRate;
					report.connection.tx_rate_kbps = association.ulTxRate;
				}

				if (rssi.has_value()) {
					report.connection.rssi_dbm = static_cast<int32_t>(*rssi);
				} else if (report.connection.signal_quality > 0) {
					report.connection.rssi_dbm = _estimate_rssi_from_quality(report.connection.signal_quality);
				}

				if (channel_number.has_value()) {
					report.connection.channel = static_cast<uint32_t>(*channel_number);
				}

				auto bss_list = _get_bss_list(handle.get(), info.InterfaceGuid);
				for (DWORD bss_index = 0; bss_index < bss_list->dwNumberOfItems; ++bss_index) {
					const auto& bss = bss_list->wlanBssEntries[bss_index];
					wifi_network_info network{};
					network.ssid = _ssid_to_string(bss.dot11Ssid);
					network.bssid = _to_mac(bss.dot11Bssid, sizeof(bss.dot11Bssid));
					network.phy_type = _phy_type_to_string(bss.dot11BssPhyType);
					network.bss_type = _bss_type_to_string(bss.dot11BssType);
					network.signal_quality = bss.uLinkQuality;
					network.rssi_dbm = static_cast<int32_t>(bss.lRssi);
					network.center_frequency_mhz = bss.ulChCenterFrequency / 1000;
					network.band = _band_from_frequency(*network.center_frequency_mhz);
					network.channel = _frequency_to_channel(*network.center_frequency_mhz);
					network.channel_width_mhz = _parse_channel_width_mhz(bss);
					network.connected = report.connection.connected && network.bssid == report.connection.bssid;

					const auto available_it = available_network_map.find(network.ssid);
					if (available_it != available_network_map.end()) {
						network.profile_name = available_it->second.profile_name;
						network.security_enabled = available_it->second.security_enabled;
						network.connectable = available_it->second.connectable;
						network.auth_algorithm = available_it->second.auth_algorithm;
						network.cipher_algorithm = available_it->second.cipher_algorithm;
					}

					if (network.connected) {
						report.connection.center_frequency_mhz = network.center_frequency_mhz;
						report.connection.channel = network.channel;
						report.connection.channel_width_mhz = network.channel_width_mhz;
					}

					report.nearby_networks.emplace_back(std::move(network));
				}

				std::sort(report.nearby_networks.begin(), report.nearby_networks.end(), [](const auto& lhs, const auto& rhs) {
					return lhs.rssi_dbm.value_or(-127) > rhs.rssi_dbm.value_or(-127);
				});

				report.connection.nearby_bss_count = static_cast<size_t>(std::count_if(report.nearby_networks.begin(), report.nearby_networks.end(), [](const auto& network) {
					return !network.connected;
				}));

				if (report.connection.connected && report.connection.channel.has_value()) {
					for (const auto& network : report.nearby_networks) {
						if (network.connected || !network.channel.has_value()) {
							continue;
						}

						if (*network.channel == *report.connection.channel) {
							++report.connection.same_channel_bss_count;
							continue;
						}

						if (network.band == "2.4 GHz" && *report.connection.channel <= 14) {
							const auto channel_gap = static_cast<int>(*network.channel) - static_cast<int>(*report.connection.channel);
							if (std::abs(channel_gap) <= 4) {
								++report.connection.adjacent_channel_bss_count;
							}
						}
					}
				}

				if (!report.connection.radio_on) {
					ctx.result.messages.emplace_back(checker_message{
						.level = severity::warning,
						.title = std::format("Wi-Fi radio is off: {}", report.interface_name),
						.description = "The wireless adapter is present, but the radio is disabled in hardware or software."
					});
				} else if (!report.connection.connected) {
					ctx.result.messages.emplace_back(checker_message{
						.level = severity::info,
						.title = std::format("Wi-Fi adapter is not connected: {}", report.interface_name),
						.description = "The wireless adapter is available, but there is no active Wi-Fi association at the moment."
					});
				} else {
					if (report.connection.signal_quality < 30 || report.connection.rssi_dbm.value_or(-65) <= -80) {
						ctx.result.messages.emplace_back(checker_message{
							.level = severity::error,
							.title = std::format("Poor Wi-Fi signal quality: {}", report.interface_name),
							.description = std::format(
								"Current SSID '{}' has weak signal quality ({}%) and RSSI {} dBm. This usually indicates a poor link budget or severe interference.",
								report.connection.ssid,
								report.connection.signal_quality,
								report.connection.rssi_dbm.value_or(-127)
							)
						});
					} else if (report.connection.signal_quality < 50 || report.connection.rssi_dbm.value_or(-65) <= -70) {
						ctx.result.messages.emplace_back(checker_message{
							.level = severity::warning,
							.title = std::format("Moderate Wi-Fi signal quality: {}", report.interface_name),
							.description = std::format(
								"Current SSID '{}' is usable, but the signal is only {}% (RSSI {} dBm). Throughput and stability may degrade.",
								report.connection.ssid,
								report.connection.signal_quality,
								report.connection.rssi_dbm.value_or(-127)
							)
						});
					}

					if (report.connection.same_channel_bss_count >= 3 || report.connection.adjacent_channel_bss_count >= 5) {
						ctx.result.messages.emplace_back(checker_message{
							.level = severity::warning,
							.title = std::format("High Wi-Fi channel interference: {}", report.interface_name),
							.description = std::format(
								"Connected channel {} has {} same-channel BSS and {} overlapping adjacent-channel BSS nearby. Co-channel contention and adjacent-channel interference are likely.",
								report.connection.channel.value_or(0),
								report.connection.same_channel_bss_count,
								report.connection.adjacent_channel_bss_count
							)
						});
					} else if (report.connection.same_channel_bss_count > 0 || report.connection.adjacent_channel_bss_count > 0) {
						ctx.result.messages.emplace_back(checker_message{
							.level = severity::info,
							.title = std::format("Nearby Wi-Fi contention detected: {}", report.interface_name),
							.description = std::format(
								"Connected channel {} has {} same-channel BSS and {} overlapping adjacent-channel BSS nearby.",
								report.connection.channel.value_or(0),
								report.connection.same_channel_bss_count,
								report.connection.adjacent_channel_bss_count
							)
						});
					}

					if (report.connection.rx_rate_kbps == 0 || report.connection.tx_rate_kbps == 0) {
						ctx.result.messages.emplace_back(checker_message{
							.level = severity::warning,
							.title = std::format("Unexpected Wi-Fi link rate: {}", report.interface_name),
							.description = "The adapter reports a connected state, but negotiated receive/transmit rates are zero. Driver or adapter telemetry may be incomplete."
						});
					}
				}

				if (report.scan_requested && !report.scan_completed) {
					ctx.result.messages.emplace_back(checker_message{
						.level = severity::info,
						.title = std::format("Wi-Fi scan did not complete synchronously: {}", report.interface_name),
						.description = "An active scan was requested, but completion was not confirmed within the wait window. Cached BSS information is still collected when available."
					});
				}

				ctx.result.wifi_interfaces.emplace_back(std::move(report));
			}
			catch (const std::exception& e) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::warning,
					.title = std::format("Wi-Fi checker failed on interface: {}", _wide_to_string(info.strInterfaceDescription)),
					.description = e.what()
				});
			}
		}
	}
}
