#include "pch.h"
#include "html_report.h"

#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <format>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../resource.h"

#pragma comment(lib, "shell32.lib")

namespace netcure::report {
	namespace {
		struct severity_counts {
			size_t errors = 0;
			size_t warnings = 0;
			size_t infos = 0;
		};

		std::string text_or_na(std::string_view text) {
			return text.empty() ? "N/A" : std::string(text);
		}

		std::string severity_key(const checkers::severity level) {
			switch (level) {
			case checkers::severity::error:
				return "error";
			case checkers::severity::warning:
				return "warning";
			case checkers::severity::info:
				return "info";
			}

			return "info";
		}

		std::string report_verdict(const severity_counts& counts) {
			if (counts.errors > 0) {
				return "Action recommended";
			}

			if (counts.warnings > 0) {
				return "Attention needed";
			}

			return "No obvious issues";
		}

		severity_counts get_severity_counts(const checkers::checker_result& result) {
			severity_counts counts;
			for (const auto& message : result.messages) {
				switch (message.level) {
				case checkers::severity::error:
					++counts.errors;
					break;
				case checkers::severity::warning:
					++counts.warnings;
					break;
				case checkers::severity::info:
					++counts.infos;
					break;
				}
			}

			return counts;
		}

		std::string now_text() {
			const auto now = std::chrono::system_clock::now();
			const auto time = std::chrono::system_clock::to_time_t(now);
			std::tm local_time{};
			localtime_s(&local_time, &time);
			return std::format(
				"{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
				local_time.tm_year + 1900,
				local_time.tm_mon + 1,
				local_time.tm_mday,
				local_time.tm_hour,
				local_time.tm_min,
				local_time.tm_sec
			);
		}

		std::string json_escape(std::string_view text) {
			std::string escaped;
			escaped.reserve(text.size() + 16);
			constexpr char hex[] = "0123456789ABCDEF";

			for (const unsigned char ch : text) {
				switch (ch) {
				case '\"':
					escaped += "\\\"";
					break;
				case '\\':
					escaped += "\\\\";
					break;
				case '\b':
					escaped += "\\b";
					break;
				case '\f':
					escaped += "\\f";
					break;
				case '\n':
					escaped += "\\n";
					break;
				case '\r':
					escaped += "\\r";
					break;
				case '\t':
					escaped += "\\t";
					break;
				case '<':
					escaped += "\\u003C";
					break;
				case '>':
					escaped += "\\u003E";
					break;
				case '&':
					escaped += "\\u0026";
					break;
				default:
					if (ch < 0x20) {
						escaped += "\\u00";
						escaped.push_back(hex[(ch >> 4) & 0x0F]);
						escaped.push_back(hex[ch & 0x0F]);
					}
					else {
						escaped.push_back(static_cast<char>(ch));
					}
					break;
				}
			}

			return escaped;
		}

		void append_json_string(std::ostringstream& json, std::string_view value) {
			json << '"' << json_escape(value) << '"';
		}

		template<typename T>
		std::string to_text(const T& value) {
			return value.to_string();
		}

		std::string to_text(const std::string& value) {
			return value;
		}

		std::string to_text(std::string_view value) {
			return std::string(value);
		}

		std::string to_text(const char* value) {
			return value == nullptr ? "" : std::string(value);
		}

		template<typename T>
		void append_optional_number(std::ostringstream& json, const std::optional<T>& value) {
			if (!value.has_value()) {
				json << "null";
				return;
			}

			json << *value;
		}

		void append_optional_ttl(std::ostringstream& json, const std::optional<uint8_t>& ttl) {
			if (!ttl.has_value()) {
				json << "null";
				return;
			}

			json << static_cast<uint32_t>(*ttl);
		}

		template<typename T>
		void append_json_string_array(std::ostringstream& json, const std::vector<T>& values) {
			json << '[';
			for (size_t i = 0; i < values.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				append_json_string(json, to_text(values[i]));
			}
			json << ']';
		}

		void append_messages_json(std::ostringstream& json, const std::vector<checkers::checker_message>& messages) {
			json << '[';
			for (size_t i = 0; i < messages.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				const auto& message = messages[i];
				json << "{\"level\":";
				append_json_string(json, severity_key(message.level));
				json << ",\"title\":";
				append_json_string(json, text_or_na(message.title));
				json << ",\"description\":";
				append_json_string(json, text_or_na(message.description));
				json << '}';
			}
			json << ']';
		}

		void append_network_interfaces_json(std::ostringstream& json, const std::vector<utils::network_interface>& adapters) {
			json << '[';
			for (size_t i = 0; i < adapters.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				const auto& adapter = adapters[i];
				json << "{\"name\":";
				append_json_string(json, text_or_na(adapter.name));
				json << ",\"up\":" << (adapter.up ? "true" : "false");
				json << ",\"virtual\":" << (adapter.is_virtual() ? "true" : "false");
				json << ",\"mac\":";
				append_json_string(json, adapter.mac_address.empty() ? "N/A" : adapter.mac_address.to_string());
				json << ",\"ipv4\":";
				append_json_string_array(json, adapter.ipv4_addresses);
				json << ",\"ipv4Gateway\":";
				append_json_string_array(json, adapter.gateway4_addresses);
				json << ",\"ipv4Dns\":";
				append_json_string_array(json, adapter.dns4_addresses);
				json << ",\"ipv6\":";
				append_json_string_array(json, adapter.ipv6_addresses);
				json << ",\"ipv6Gateway\":";
				append_json_string_array(json, adapter.gateway6_addresses);
				json << ",\"ipv6Dns\":";
				append_json_string_array(json, adapter.dns6_addresses);
				json << '}';
			}
			json << ']';
		}

		void append_wifi_json(std::ostringstream& json, const std::vector<checkers::wifi_interface_report>& wifi_interfaces) {
			json << '[';
			for (size_t i = 0; i < wifi_interfaces.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				const auto& wifi = wifi_interfaces[i];
				json << "{\"interfaceName\":";
				append_json_string(json, text_or_na(wifi.interface_name));
				json << ",\"description\":";
				append_json_string(json, text_or_na(wifi.description));
				json << ",\"scanRequested\":" << (wifi.scan_requested ? "true" : "false");
				json << ",\"scanCompleted\":" << (wifi.scan_completed ? "true" : "false");
				json << ",\"connection\":{";
				json << "\"connected\":" << (wifi.connection.connected ? "true" : "false");
				json << ",\"radioOn\":" << (wifi.connection.radio_on ? "true" : "false");
				json << ",\"state\":";
				append_json_string(json, text_or_na(wifi.connection.state));
				json << ",\"profileName\":";
				append_json_string(json, text_or_na(wifi.connection.profile_name));
				json << ",\"ssid\":";
				append_json_string(json, text_or_na(wifi.connection.ssid));
				json << ",\"bssid\":";
				append_json_string(json, wifi.connection.bssid.empty() ? "N/A" : wifi.connection.bssid.to_string());
				json << ",\"phyType\":";
				append_json_string(json, text_or_na(wifi.connection.phy_type));
				json << ",\"bssType\":";
				append_json_string(json, text_or_na(wifi.connection.bss_type));
				json << ",\"authAlgorithm\":";
				append_json_string(json, text_or_na(wifi.connection.auth_algorithm));
				json << ",\"cipherAlgorithm\":";
				append_json_string(json, text_or_na(wifi.connection.cipher_algorithm));
				json << ",\"signalQuality\":" << wifi.connection.signal_quality;
				json << ",\"rssiDbm\":";
				append_optional_number(json, wifi.connection.rssi_dbm);
				json << ",\"centerFrequencyMhz\":";
				append_optional_number(json, wifi.connection.center_frequency_mhz);
				json << ",\"channel\":";
				append_optional_number(json, wifi.connection.channel);
				json << ",\"channelWidthMhz\":";
				append_optional_number(json, wifi.connection.channel_width_mhz);
				json << ",\"rxRateKbps\":" << wifi.connection.rx_rate_kbps;
				json << ",\"txRateKbps\":" << wifi.connection.tx_rate_kbps;
				json << ",\"unicastRxPackets\":" << wifi.connection.unicast_rx_packets;
				json << ",\"unicastTxPackets\":" << wifi.connection.unicast_tx_packets;
				json << ",\"failedTxPackets\":" << wifi.connection.failed_tx_packets;
				json << ",\"nearbyBssCount\":" << wifi.connection.nearby_bss_count;
				json << ",\"sameChannelBssCount\":" << wifi.connection.same_channel_bss_count;
				json << ",\"overlappingChannelBssCount\":" << wifi.connection.overlapping_channel_bss_count;
				json << "},\"nearbyNetworks\":[";

				for (size_t n = 0; n < wifi.nearby_networks.size(); ++n) {
					if (n > 0) {
						json << ',';
					}

					const auto& network = wifi.nearby_networks[n];
					json << "{\"ssid\":";
					append_json_string(json, text_or_na(network.ssid));
					json << ",\"bssid\":";
					append_json_string(json, network.bssid.empty() ? "N/A" : network.bssid.to_string());
					json << ",\"profileName\":";
					append_json_string(json, text_or_na(network.profile_name));
					json << ",\"phyType\":";
					append_json_string(json, text_or_na(network.phy_type));
					json << ",\"bssType\":";
					append_json_string(json, text_or_na(network.bss_type));
					json << ",\"authAlgorithm\":";
					append_json_string(json, text_or_na(network.auth_algorithm));
					json << ",\"cipherAlgorithm\":";
					append_json_string(json, text_or_na(network.cipher_algorithm));
					json << ",\"band\":";
					append_json_string(json, text_or_na(network.band));
					json << ",\"securityEnabled\":" << (network.security_enabled ? "true" : "false");
					json << ",\"connectable\":" << (network.connectable ? "true" : "false");
					json << ",\"connected\":" << (network.connected ? "true" : "false");
					json << ",\"signalQuality\":" << network.signal_quality;
					json << ",\"rssiDbm\":";
					append_optional_number(json, network.rssi_dbm);
					json << ",\"centerFrequencyMhz\":";
					append_optional_number(json, network.center_frequency_mhz);
					json << ",\"channel\":";
					append_optional_number(json, network.channel);
					json << ",\"channelWidthMhz\":";
					append_optional_number(json, network.channel_width_mhz);
					json << '}';
				}

				json << "]}";
			}
			json << ']';
		}

		void append_ping_targets_json(std::ostringstream& json, const std::vector<checkers::ping_target_report>& ping_targets) {
			json << '[';
			for (size_t i = 0; i < ping_targets.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				const auto& target = ping_targets[i];
				json << "{\"category\":";
				append_json_string(json, text_or_na(target.category));
				json << ",\"targetName\":";
				append_json_string(json, text_or_na(target.target_name));
				json << ",\"address\":";
				append_json_string(json, text_or_na(target.address));
				json << ",\"attempts\":" << target.attempts;
				json << ",\"timeoutMs\":" << target.timeout_ms;
				json << ",\"intervalMs\":" << target.interval_ms;
				json << ",\"replies\":" << target.replies;
				json << ",\"losses\":" << target.losses;
				json << ",\"timeoutCount\":" << target.timeout_count;
				json << ",\"lossRate\":" << target.loss_rate;
				json << ",\"minRttMs\":";
				append_optional_number(json, target.min_rtt_ms);
				json << ",\"maxRttMs\":";
				append_optional_number(json, target.max_rtt_ms);
				json << ",\"avgRttMs\":";
				append_optional_number(json, target.avg_rtt_ms);
				json << ",\"jitterMs\":";
				append_optional_number(json, target.jitter_ms);
				json << ",\"lastError\":";
				append_json_string(json, text_or_na(target.last_error));
				json << ",\"attemptDetails\":[";

				for (size_t attempt_index = 0; attempt_index < target.attempt_details.size(); ++attempt_index) {
					if (attempt_index > 0) {
						json << ',';
					}

					const auto& attempt = target.attempt_details[attempt_index];
					json << "{\"sequence\":" << attempt.sequence;
					json << ",\"success\":" << (attempt.success ? "true" : "false");
					json << ",\"timedOut\":" << (attempt.timed_out ? "true" : "false");
					json << ",\"rttMs\":";
					append_optional_number(json, attempt.rtt_ms);
					json << ",\"ttl\":";
					append_optional_ttl(json, attempt.ttl);
					json << ",\"statusCode\":" << attempt.status_code;
					json << ",\"status\":";
					append_json_string(json, text_or_na(attempt.status));
					json << '}';
				}

				json << "]}";
			}
			json << ']';
		}

		void append_host_environment_json(std::ostringstream& json, const checkers::host_environment_report& environment) {
			json << "{\"computerName\":";
			append_json_string(json, text_or_na(environment.computer_name));
			json << ",\"systemManufacturer\":";
			append_json_string(json, text_or_na(environment.system_manufacturer));
			json << ",\"systemModel\":";
			append_json_string(json, text_or_na(environment.system_model));
			json << ",\"osName\":";
			append_json_string(json, text_or_na(environment.os_name));
			json << ",\"osVersion\":";
			append_json_string(json, text_or_na(environment.os_version));
			json << ",\"osBuild\":";
			append_json_string(json, text_or_na(environment.os_build));
			json << ",\"osDisplayVersion\":";
			append_json_string(json, text_or_na(environment.os_display_version));
			json << ",\"architecture\":";
			append_json_string(json, text_or_na(environment.architecture));
			json << ",\"networkAdapterModels\":";
			append_json_string_array(json, environment.network_adapter_models);
			json << '}';
		}

		template<typename T>
		void append_routes_json(std::ostringstream& json, const std::vector<utils::route_entry<T>>& routes) {
			json << '[';
			for (size_t i = 0; i < routes.size(); ++i) {
				if (i > 0) {
					json << ',';
				}

				const auto& route = routes[i];
				json << "{\"destination\":";
				append_json_string(json, route.destination.to_string());
				json << ",\"nextHop\":";
				append_json_string(json, route.next_hop.to_string());
				json << ",\"interface\":";
				append_json_string(json, text_or_na(route.interface));
				json << ",\"metric\":" << route.metric;
				json << '}';
			}
			json << ']';
		}

		std::filesystem::path resolve_output_path(const std::filesystem::path& output_path, std::string_view fallback_name) {
			auto resolved_path = output_path.empty()
				? std::filesystem::current_path() / fallback_name
				: output_path;
			resolved_path = std::filesystem::absolute(resolved_path);

			if (resolved_path.has_parent_path()) {
				std::filesystem::create_directories(resolved_path.parent_path());
			}

			return resolved_path;
		}

		void write_utf8_file(const std::filesystem::path& output_path, std::string_view content, const bool include_bom) {
			std::ofstream file(output_path, std::ios::binary | std::ios::trunc);
			if (!file.is_open()) {
				throw std::runtime_error(std::format("Failed to create report file: {}", output_path.string()));
			}

			if (include_bom) {
				file.write("\xEF\xBB\xBF", 3);
			}

			file.write(content.data(), static_cast<std::streamsize>(content.size()));
			file.close();
		}

		std::string load_resource_text(const UINT resource_id) {
			const auto module = GetModuleHandleW(nullptr);
			if (module == nullptr) {
				throw std::runtime_error("Unable to locate the current module for report resources.");
			}

			const HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(resource_id), RT_RCDATA);
			if (resource == nullptr) {
				throw std::runtime_error(std::format("Embedded frontend resource {} was not found.", resource_id));
			}

			const DWORD size = SizeofResource(module, resource);
			const HGLOBAL loaded_resource = LoadResource(module, resource);
			if (loaded_resource == nullptr || size == 0) {
				throw std::runtime_error(std::format("Embedded frontend resource {} could not be loaded.", resource_id));
			}

			const void* data = LockResource(loaded_resource);
			if (data == nullptr) {
				throw std::runtime_error(std::format("Embedded frontend resource {} is empty.", resource_id));
			}

			return std::string(static_cast<const char*>(data), static_cast<size_t>(size));
		}

		void replace_all(std::string& text, const std::string_view search, const std::string_view replace_with) {
			size_t pos = 0;
			while ((pos = text.find(search, pos)) != std::string::npos) {
				text.replace(pos, search.size(), replace_with);
				pos += replace_with.size();
			}
		}

		void remove_known_asset_tags(std::string& html) {
			replace_all(html, "<link rel=\"stylesheet\" crossorigin href=\"/assets/report-app.css\">", "");
			replace_all(html, "<link rel=\"stylesheet\" crossorigin href=\"./assets/report-app.css\">", "");
			replace_all(html, "<script type=\"module\" crossorigin src=\"/assets/report-app.js\"></script>", "");
			replace_all(html, "<script type=\"module\" crossorigin src=\"./assets/report-app.js\"></script>", "");
		}

		std::string escape_inline_script(std::string script_text) {
			replace_all(script_text, "</script", "<\\/script");
			return script_text;
		}

		std::string render_document(std::string_view report_json) {
			auto html = load_resource_text(IDR_NETCURE_FRONTEND_HTML);
			const auto css = load_resource_text(IDR_NETCURE_FRONTEND_CSS);
			const auto js = escape_inline_script(load_resource_text(IDR_NETCURE_FRONTEND_JS));

			remove_known_asset_tags(html);
			replace_all(
				html,
				"<!-- NETCURE_INLINE_STYLE -->",
				std::format("<style>\n{}\n</style>", css)
			);
			replace_all(
				html,
				"<!-- NETCURE_REPORT_DATA -->",
				std::format("<script id=\"netcure-report-data\" type=\"application/json\">{}</script>", report_json)
			);
			replace_all(
				html,
				"<!-- NETCURE_INLINE_SCRIPT -->",
				std::format("<script type=\"module\">\n{}\n</script>", js)
			);

			return html;
		}
	}

	std::string build_report_json(const checkers::checker_result& result) {
		const auto counts = get_severity_counts(result);
		const auto adapters_up = std::count_if(result.network_interfaces.begin(), result.network_interfaces.end(), [](const auto& adapter) {
			return adapter.up;
		});
		const auto connected_wifi_count = std::count_if(result.wifi_interfaces.begin(), result.wifi_interfaces.end(), [](const auto& wifi) {
			return wifi.connection.connected;
		});
		const auto default_gateway_count = std::count_if(result.route4_table.begin(), result.route4_table.end(), [](const auto& route) {
			return route.destination.prefix_length == 0;
		});
		const auto public_ping_successes = std::count_if(result.ping_targets.begin(), result.ping_targets.end(), [](const auto& target) {
			return target.category == "public" && target.replies > 0;
		});
		const auto public_ping_total = std::count_if(result.ping_targets.begin(), result.ping_targets.end(), [](const auto& target) {
			return target.category == "public";
		});

		std::ostringstream json;
		json << '{';
		json << "\"generatedAt\":";
		append_json_string(json, now_text());
		json << ",\"summary\":{";
		json << "\"verdict\":";
		append_json_string(json, report_verdict(counts));
		json << ",\"errors\":" << counts.errors;
		json << ",\"warnings\":" << counts.warnings;
		json << ",\"infos\":" << counts.infos;
		json << ",\"adaptersUp\":" << adapters_up;
		json << ",\"adaptersTotal\":" << result.network_interfaces.size();
		json << ",\"connectedWifiCount\":" << connected_wifi_count;
		json << ",\"publicPingSuccesses\":" << public_ping_successes;
		json << ",\"publicPingTotal\":" << public_ping_total;
		json << ",\"defaultGatewayCount\":" << default_gateway_count;
		json << ",\"pingTargetCount\":" << result.ping_targets.size();
		json << "},\"messages\":";
		append_messages_json(json, result.messages);
		json << ",\"networkInterfaces\":";
		append_network_interfaces_json(json, result.network_interfaces);
		json << ",\"wifiInterfaces\":";
		append_wifi_json(json, result.wifi_interfaces);
		json << ",\"pingTargets\":";
		append_ping_targets_json(json, result.ping_targets);
		json << ",\"hostEnvironment\":";
		append_host_environment_json(json, result.host_environment);
		json << ",\"route4Table\":";
		append_routes_json(json, result.route4_table);
		json << ",\"route6Table\":";
		append_routes_json(json, result.route6_table);
		json << '}';
		return json.str();
	}

	std::filesystem::path write_report_json(std::string_view report_json, const std::filesystem::path& output_path) {
		const auto resolved_path = resolve_output_path(output_path, "netcure-report.json");
		write_utf8_file(resolved_path, report_json, true);
		return resolved_path;
	}

	std::filesystem::path write_html_report(std::string_view report_json, const std::filesystem::path& output_path) {
		const auto resolved_path = resolve_output_path(output_path, "netcure-report.html");
		const auto document = render_document(report_json);
		write_utf8_file(resolved_path, document, true);
		return resolved_path;
	}

	bool open_report_in_browser(const std::filesystem::path& report_path) {
		const auto result = reinterpret_cast<intptr_t>(
			ShellExecuteW(
				nullptr,
				L"open",
				report_path.c_str(),
				nullptr,
				report_path.parent_path().empty() ? nullptr : report_path.parent_path().c_str(),
				SW_SHOWNORMAL
			)
		);
		return result > 32;
	}
}
