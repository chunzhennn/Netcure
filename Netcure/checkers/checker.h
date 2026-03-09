#pragma once
#ifndef NETCURE_CHECKER_H
#define NETCURE_CHECKER_H

#include<vector>
#include<string>
#include<map>
#include<variant>
#include<utility>
#include<iostream>
#include<concepts>
#include<optional>

#include "../utils.h"

namespace netcure::checkers {

	enum class severity {
		info,
		warning,
		error,
	};

	struct checker_message {
		severity level;
		std::string title;
		std::string description;
	};

	struct wifi_network_info {
		std::string ssid;
		utils::mac bssid;
		std::string profile_name;
		std::string phy_type;
		std::string bss_type;
		std::string auth_algorithm;
		std::string cipher_algorithm;
		std::string band;
		bool security_enabled = false;
		bool connectable = false;
		bool connected = false;
		uint32_t signal_quality = 0;
		std::optional<int32_t> rssi_dbm;
		std::optional<uint32_t> center_frequency_mhz;
		std::optional<uint32_t> channel;
		std::optional<uint32_t> channel_width_mhz;
	};

	struct wifi_connection_quality {
		bool connected = false;
		bool radio_on = true;
		std::string state;
		std::string profile_name;
		std::string ssid;
		utils::mac bssid;
		std::string phy_type;
		std::string bss_type;
		std::string auth_algorithm;
		std::string cipher_algorithm;
		uint32_t signal_quality = 0;
		std::optional<int32_t> rssi_dbm;
		std::optional<uint32_t> center_frequency_mhz;
		std::optional<uint32_t> channel;
		std::optional<uint32_t> channel_width_mhz;
		uint32_t rx_rate_kbps = 0;
		uint32_t tx_rate_kbps = 0;
		uint64_t unicast_rx_packets = 0;
		uint64_t unicast_tx_packets = 0;
		uint64_t failed_tx_packets = 0;
		size_t nearby_bss_count = 0;
		size_t same_channel_bss_count = 0;
		size_t adjacent_channel_bss_count = 0;
	};

	struct wifi_interface_report {
		if_id_type interface_id{};
		std::string interface_name;
		std::string description;
		bool scan_requested = false;
		bool scan_completed = false;
		wifi_connection_quality connection;
		std::vector<wifi_network_info> nearby_networks;
	};

	struct checker_result {
		std::vector<utils::network_interface> network_interfaces;
		std::vector<checker_message> messages;
		std::vector<utils::route_entry<utils::ipv4_addr>> route4_table;
		std::vector<utils::route_entry<utils::ipv6_addr>> route6_table;
      std::vector<wifi_interface_report> wifi_interfaces;
	};

	struct checker_context {
		bool has_wireless_adapter = false;
		int active_adapter_count = 0;
		// All report-related data is stored in result
		checker_result result;
	};

	struct checker {
		virtual ~checker() = default;
		virtual bool available(const checker_context&) const = 0;
		virtual void run(checker_context&) = 0;
	};

	template<typename... Ts>
	requires (std::derived_from<Ts, checker> && ...)
	checker_result run_checkers() {
		checker_context ctx;
		// Create a vector of checkers
		std::vector<std::unique_ptr<checker>> checkers;
		(checkers.emplace_back(std::make_unique<Ts>()), ...);

		// Run each checker
		for (auto& c : checkers) {
			if (c->available(ctx)) {
				try {
					c->run(ctx);
				}
				catch (const std::exception& e) {
					ctx.result.messages.emplace_back(
						checker_message{
							severity::error,
							"Checker Error",
							std::format("An error occurred while running {}: {}", typeid(*c).name(), e.what())
						}
					);
					std::cerr << ctx.result.messages.back().description << std::endl;
				}
			}
		}
		return std::move(ctx.result);
	}
}

#endif // NETCURE_CHECKER_H