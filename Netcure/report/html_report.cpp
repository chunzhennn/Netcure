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
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "shell32.lib")

namespace netcure::report {
	namespace {
		struct severity_counts {
			size_t errors = 0;
			size_t warnings = 0;
			size_t infos = 0;
		};

		std::string html_escape(std::string_view text) {
			std::string escaped;
			escaped.reserve(text.size());
			for (const char ch : text) {
				switch (ch) {
				case '&':
					escaped += "&amp;";
					break;
				case '<':
					escaped += "&lt;";
					break;
				case '>':
					escaped += "&gt;";
					break;
				case '"':
					escaped += "&quot;";
					break;
				case '\'':
					escaped += "&#39;";
					break;
				default:
					escaped.push_back(ch);
					break;
				}
			}
			return escaped;
		}

		std::string text_or_na(std::string_view text) {
			return text.empty() ? "N/A" : std::string(text);
		}

		std::string bool_text(const bool value, std::string_view true_text = "Yes", std::string_view false_text = "No") {
			return value ? std::string(true_text) : std::string(false_text);
		}

		template<typename T>
		std::string optional_number_text(const std::optional<T>& value, const std::string& pattern) {
			if (!value.has_value()) {
				return "N/A";
			}
			return std::vformat(pattern, std::make_format_args(*value));
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

		std::string severity_label(const checkers::severity level) {
			switch (level) {
			case checkers::severity::error:
				return "Error";
			case checkers::severity::warning:
				return "Warning";
			case checkers::severity::info:
				return "Info";
			}
			return "Info";
		}

		std::string severity_class(const checkers::severity level) {
			switch (level) {
			case checkers::severity::error:
				return "severity-error";
			case checkers::severity::warning:
				return "severity-warning";
			case checkers::severity::info:
				return "severity-info";
			}
			return "severity-info";
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

		template<typename T>
		std::string to_text(const T& value) {
			return value.to_string();
		}

		std::string to_text(const std::string& value) {
			return value;
		}

		std::string to_text(const char* value) {
			return value == nullptr ? "" : std::string(value);
		}

		template<typename T>
		std::string render_pills(const std::vector<T>& values) {
			if (values.empty()) {
				return "<span class=\"muted\">N/A</span>";
			}

			std::ostringstream html;
			html << "<div class=\"pill-list\">";
			for (const auto& value : values) {
				html << "<span class=\"pill\">" << html_escape(to_text(value)) << "</span>";
			}
			html << "</div>";
			return html.str();
		}

		void append_stat(std::ostringstream& html, std::string_view label, std::string_view value) {
			html << "<div class=\"stat-card\">"
				 << "<div class=\"stat-label\">" << html_escape(label) << "</div>"
				 << "<div class=\"stat-value\">" << html_escape(value) << "</div>"
				 << "</div>";
		}

		void append_kv(std::ostringstream& html, std::string_view label, std::string_view value) {
			html << "<div class=\"kv-item\">"
				 << "<div class=\"kv-label\">" << html_escape(label) << "</div>"
				 << "<div class=\"kv-value\">" << html_escape(value) << "</div>"
				 << "</div>";
		}

		void append_kv_html(std::ostringstream& html, std::string_view label, const std::string& value_html) {
			html << "<div class=\"kv-item\">"
				 << "<div class=\"kv-label\">" << html_escape(label) << "</div>"
				 << "<div class=\"kv-value\">" << value_html << "</div>"
				 << "</div>";
		}

		std::string render_observed_ttls(const checkers::ping_target_report& report) {
			std::vector<uint32_t> ttls;
			for (const auto& attempt : report.attempt_details) {
				if (attempt.ttl.has_value()) {
					ttls.emplace_back(*attempt.ttl);
				}
			}

			if (ttls.empty()) {
				return "N/A";
			}

			std::ranges::sort(ttls);
			ttls.erase(std::unique(ttls.begin(), ttls.end()), ttls.end());

			std::ostringstream text;
			for (size_t index = 0; index < ttls.size(); ++index) {
				if (index > 0) {
					text << ", ";
				}
				text << ttls[index];
			}
			return text.str();
		}

		std::string ttl_text(const std::optional<uint8_t>& ttl) {
			if (!ttl.has_value()) {
				return "N/A";
			}
			return std::format("{}", static_cast<uint32_t>(*ttl));
		}

		std::string render_ping_chart(const checkers::ping_target_report& report) {
			if (report.attempt_details.empty()) {
				return "<div class=\"empty-state\">No ping attempt details were captured.</div>";
			}

			constexpr double width = 640.0;
			constexpr double height = 180.0;
			constexpr double left = 40.0;
			constexpr double right = 12.0;
			constexpr double top = 12.0;
			constexpr double bottom = 28.0;
			const double chart_width = width - left - right;
			const double chart_height = height - top - bottom;

			uint32_t max_rtt = 1;
			for (const auto& attempt : report.attempt_details) {
				if (attempt.rtt_ms.has_value()) {
					max_rtt = (std::max)(max_rtt, *attempt.rtt_ms);
				}
			}

			auto x_for = [&](const size_t index) {
				if (report.attempt_details.size() <= 1) {
					return left + chart_width / 2.0;
				}
				return left + (static_cast<double>(index) * chart_width / static_cast<double>(report.attempt_details.size() - 1));
			};

			auto y_for = [&](const uint32_t rtt_ms) {
				const double normalized = static_cast<double>(rtt_ms) / static_cast<double>(max_rtt);
				return top + (chart_height * (1.0 - normalized));
			};

			std::ostringstream svg;
			svg << "<svg class=\"ping-chart\" viewBox=\"0 0 " << width << ' ' << height << "\" role=\"img\" aria-label=\"Ping round-trip time chart\">";
			svg << "<line class=\"chart-axis\" x1=\"" << left << "\" y1=\"" << (height - bottom) << "\" x2=\"" << (width - right) << "\" y2=\"" << (height - bottom) << "\" />";
			svg << "<line class=\"chart-axis\" x1=\"" << left << "\" y1=\"" << top << "\" x2=\"" << left << "\" y2=\"" << (height - bottom) << "\" />";
			svg << "<text class=\"chart-label\" x=\"" << left << "\" y=\"" << (height - 8.0) << "\">1</text>";
			svg << "<text class=\"chart-label\" x=\"" << (width - right - 8.0) << "\" y=\"" << (height - 8.0) << "\" text-anchor=\"end\">" << report.attempt_details.size() << "</text>";
			svg << "<text class=\"chart-label\" x=\"" << (left - 8.0) << "\" y=\"" << (top + 4.0) << "\" text-anchor=\"end\">" << max_rtt << " ms</text>";
			svg << "<text class=\"chart-label\" x=\"" << (left - 8.0) << "\" y=\"" << (height - bottom + 4.0) << "\" text-anchor=\"end\">0</text>";

			std::ostringstream current_segment;
			bool has_segment = false;
			for (size_t index = 0; index < report.attempt_details.size(); ++index) {
				const auto& attempt = report.attempt_details[index];
				if (attempt.rtt_ms.has_value()) {
					const auto x = x_for(index);
					const auto y = y_for(*attempt.rtt_ms);
					if (has_segment) {
						current_segment << ' ';
					}
					current_segment << x << ',' << y;
					has_segment = true;
				} else if (has_segment) {
					svg << "<polyline class=\"chart-line\" points=\"" << current_segment.str() << "\" />";
					current_segment.str("");
					current_segment.clear();
					has_segment = false;
				}
			}
			if (has_segment) {
				svg << "<polyline class=\"chart-line\" points=\"" << current_segment.str() << "\" />";
			}

			for (size_t index = 0; index < report.attempt_details.size(); ++index) {
				const auto& attempt = report.attempt_details[index];
				const auto x = x_for(index);
				if (attempt.rtt_ms.has_value()) {
					const auto y = y_for(*attempt.rtt_ms);
					svg << "<circle class=\"chart-point-success\" cx=\"" << x << "\" cy=\"" << y << "\" r=\"4\">"
						<< "<title>Attempt " << attempt.sequence << ": " << *attempt.rtt_ms << " ms"
						<< (attempt.ttl.has_value() ? std::format(", TTL {}", static_cast<uint32_t>(*attempt.ttl)) : "")
						<< "</title>"
						<< "</circle>";
				} else {
					const auto y = height - bottom - 4.0;
					svg << "<circle class=\"" << (attempt.timed_out ? "chart-point-timeout" : "chart-point-failed")
						<< "\" cx=\"" << x << "\" cy=\"" << y << "\" r=\"4\">"
						<< "<title>Attempt " << attempt.sequence << ": " << html_escape(attempt.status)
						<< (attempt.ttl.has_value() ? std::format(", TTL {}", static_cast<uint32_t>(*attempt.ttl)) : "")
						<< "</title>"
						<< "</circle>";
				}
			}

			svg << "</svg>";
			return svg.str();
		}

		void append_messages(std::ostringstream& html, const checkers::checker_result& result) {
			html << "<section id=\"findings\" class=\"page-section\">"
				 << "<details open><summary>Findings</summary>"
				 << "<div class=\"toolbar\" role=\"group\" aria-label=\"Filter findings by severity\">"
				 << "<button class=\"filter-button active\" data-filter=\"all\" aria-pressed=\"true\">All</button>"
				 << "<button class=\"filter-button\" data-filter=\"error\" aria-pressed=\"false\">Errors</button>"
				 << "<button class=\"filter-button\" data-filter=\"warning\" aria-pressed=\"false\">Warnings</button>"
				 << "<button class=\"filter-button\" data-filter=\"info\" aria-pressed=\"false\">Info</button>"
				 << "</div>";

			if (result.messages.empty()) {
				html << "<div class=\"empty-state\">No checker messages were produced.</div>";
			} else {
				for (const auto level : { checkers::severity::error, checkers::severity::warning, checkers::severity::info }) {
					bool has_group = false;
					for (const auto& message : result.messages) {
						if (message.level == level) {
							has_group = true;
							break;
						}
					}
					if (!has_group) {
						continue;
					}

					const auto level_class = severity_class(level);
					const auto level_name = severity_label(level);
					html << "<div class=\"finding-group\" data-group=\"" << html_escape(level_name) << "\">"
						 << "<h3>" << html_escape(level_name) << "</h3>";
					for (const auto& message : result.messages) {
						if (message.level != level) {
							continue;
						}
						html << "<article class=\"finding-card " << level_class << "\" data-severity=\"" << html_escape(level_name) << "\">"
							 << "<div class=\"finding-title-row\">"
							 << "<span class=\"severity-pill " << level_class << "\">" << html_escape(level_name) << "</span>"
							 << "<h4>" << html_escape(text_or_na(message.title)) << "</h4>"
							 << "</div>"
							 << "<p>" << html_escape(text_or_na(message.description)) << "</p>"
							 << "</article>";
					}
					html << "</div>";
				}
			}

			html << "</details></section>";
		}

		void append_interfaces(std::ostringstream& html, const checkers::checker_result& result) {
			html << "<section id=\"interfaces\" class=\"page-section\">"
				 << "<details open><summary>Adapters</summary>";

			if (result.network_interfaces.empty()) {
				html << "<div class=\"empty-state\">No network adapters were collected.</div>";
			} else {
				html << "<div class=\"card-grid\">";
				for (const auto& adapter : result.network_interfaces) {
					html << "<article class=\"panel-card\">"
						 << "<h3>" << html_escape(text_or_na(adapter.name)) << "</h3>"
						 << "<div class=\"kv-grid\">";
					append_kv(html, "State", adapter.up ? "Up" : "Down");
					append_kv(html, "Virtual", adapter.is_virtual() ? "Likely" : "No");
					append_kv(html, "MAC", adapter.mac_address.empty() ? "N/A" : adapter.mac_address.to_string());
					append_kv_html(html, "IPv4", render_pills(adapter.ipv4_addresses));
					append_kv_html(html, "IPv4 Gateway", render_pills(adapter.gateway4_addresses));
					append_kv_html(html, "IPv4 DNS", render_pills(adapter.dns4_addresses));
					append_kv_html(html, "IPv6", render_pills(adapter.ipv6_addresses));
					append_kv_html(html, "IPv6 Gateway", render_pills(adapter.gateway6_addresses));
					append_kv_html(html, "IPv6 DNS", render_pills(adapter.dns6_addresses));
					html << "</div></article>";
				}
				html << "</div>";
			}

			html << "</details></section>";
		}

		void append_wifi(std::ostringstream& html, const checkers::checker_result& result) {
			html << "<section id=\"wifi\" class=\"page-section\">"
				 << "<details open><summary>Wi-Fi</summary>";

			if (result.wifi_interfaces.empty()) {
				html << "<div class=\"empty-state\">No Wi-Fi report data was collected.</div>";
			} else {
				for (size_t index = 0; index < result.wifi_interfaces.size(); ++index) {
					const auto& wifi = result.wifi_interfaces[index];
					html << "<details class=\"panel-card nested-panel\" " << (index == 0 ? "open" : "") << ">"
						 << "<summary>" << html_escape(text_or_na(wifi.interface_name))
						 << "<span class=\"summary-meta\">" << html_escape(text_or_na(wifi.connection.state)) << "</span>"
						 << "</summary>"
						 << "<div class=\"kv-grid\">";
					append_kv(html, "Description", text_or_na(wifi.description));
					append_kv(html, "Scan requested", bool_text(wifi.scan_requested));
					append_kv(html, "Scan completed", bool_text(wifi.scan_completed));
					append_kv(html, "Connected", bool_text(wifi.connection.connected));
					append_kv(html, "Radio on", bool_text(wifi.connection.radio_on));
					append_kv(html, "State", text_or_na(wifi.connection.state));
					append_kv(html, "Profile", text_or_na(wifi.connection.profile_name));
					append_kv(html, "SSID", text_or_na(wifi.connection.ssid));
					append_kv(html, "BSSID", wifi.connection.bssid.empty() ? "N/A" : wifi.connection.bssid.to_string());
					append_kv(html, "Signal quality", std::format("{}%", wifi.connection.signal_quality));
					append_kv(html, "RSSI", optional_number_text(wifi.connection.rssi_dbm, "{} dBm"));
					append_kv(html, "Channel", optional_number_text(wifi.connection.channel, "{}"));
					append_kv(html, "Center frequency", optional_number_text(wifi.connection.center_frequency_mhz, "{} MHz"));
					append_kv(html, "Channel width", optional_number_text(wifi.connection.channel_width_mhz, "{} MHz"));
					append_kv(html, "PHY", text_or_na(wifi.connection.phy_type));
					append_kv(html, "BSS type", text_or_na(wifi.connection.bss_type));
					append_kv(html, "Authentication", text_or_na(wifi.connection.auth_algorithm));
					append_kv(html, "Cipher", text_or_na(wifi.connection.cipher_algorithm));
					append_kv(html, "RX rate", std::format("{} Kbps", wifi.connection.rx_rate_kbps));
					append_kv(html, "TX rate", std::format("{} Kbps", wifi.connection.tx_rate_kbps));
					append_kv(html, "RX packets", std::format("{}", wifi.connection.unicast_rx_packets));
					append_kv(html, "TX packets", std::format("{}", wifi.connection.unicast_tx_packets));
					append_kv(html, "Failed TX", std::format("{}", wifi.connection.failed_tx_packets));
					append_kv(html, "Nearby BSS", std::format("{}", wifi.connection.nearby_bss_count));
					append_kv(html, "Same channel", std::format("{}", wifi.connection.same_channel_bss_count));
					append_kv(html, "Overlapping BSS", std::format("{}", wifi.connection.overlapping_channel_bss_count));
					html << "</div>";

					if (wifi.nearby_networks.empty()) {
						html << "<div class=\"empty-state\">No nearby networks were captured.</div>";
					} else {
						html << "<div class=\"table-wrap\"><table><thead><tr>"
							 << "<th>SSID</th><th>BSSID</th><th>Signal</th><th>RSSI</th><th>Channel</th><th>Width</th><th>Band</th><th>Security</th><th>Connectable</th>"
							 << "</tr></thead><tbody>";
						for (const auto& network : wifi.nearby_networks) {
							html << "<tr>"
								 << "<td>" << html_escape(text_or_na(network.ssid)) << "</td>"
								 << "<td>" << html_escape(network.bssid.empty() ? "N/A" : network.bssid.to_string()) << "</td>"
								 << "<td>" << network.signal_quality << "%</td>"
								 << "<td>" << html_escape(optional_number_text(network.rssi_dbm, "{} dBm")) << "</td>"
								 << "<td>" << html_escape(optional_number_text(network.channel, "{}")) << "</td>"
								 << "<td>" << html_escape(optional_number_text(network.channel_width_mhz, "{} MHz")) << "</td>"
								 << "<td>" << html_escape(text_or_na(network.band)) << "</td>"
								 << "<td>" << html_escape(bool_text(network.security_enabled, "Secured", "Open")) << "</td>"
								 << "<td>" << html_escape(bool_text(network.connectable)) << "</td>"
								 << "</tr>";
						}
						html << "</tbody></table></div>";
					}

					html << "</details>";
				}
			}

			html << "</details></section>";
		}

		void append_ping(std::ostringstream& html, const checkers::checker_result& result) {
			html << "<section id=\"ping\" class=\"page-section\">"
				 << "<details open><summary>Ping diagnostics</summary>";

			if (result.ping_targets.empty()) {
				html << "<div class=\"empty-state\">No ping targets were tested.</div>";
			} else {
				for (size_t index = 0; index < result.ping_targets.size(); ++index) {
					const auto& target = result.ping_targets[index];
					html << "<details class=\"panel-card nested-panel\" " << (index == 0 ? "open" : "") << ">"
						 << "<summary>" << html_escape(text_or_na(target.target_name))
						 << "<span class=\"summary-meta\">" << html_escape(target.address) << "</span>"
						 << "</summary>"
						 << "<div class=\"kv-grid\">";
					append_kv(html, "Category", text_or_na(target.category));
					append_kv(html, "Address", text_or_na(target.address));
					append_kv(html, "Attempts", std::format("{}", target.attempts));
					append_kv(html, "Interval", std::format("{} ms", target.interval_ms));
					append_kv(html, "Timeout", std::format("{} ms", target.timeout_ms));
					append_kv(html, "Replies", std::format("{}", target.replies));
					append_kv(html, "Losses", std::format("{}", target.losses));
					append_kv(html, "Timeouts", std::format("{}", target.timeout_count));
					append_kv(html, "Loss rate", std::format("{:.1f}%", target.loss_rate));
					append_kv(html, "Min RTT", optional_number_text(target.min_rtt_ms, "{} ms"));
					append_kv(html, "Max RTT", optional_number_text(target.max_rtt_ms, "{} ms"));
					append_kv(html, "Avg RTT", optional_number_text(target.avg_rtt_ms, "{:.1f} ms"));
					append_kv(html, "Jitter", optional_number_text(target.jitter_ms, "{:.1f} ms"));
					append_kv(html, "Observed TTL", render_observed_ttls(target));
					append_kv(html, "Last error", text_or_na(target.last_error));
					html << "</div>"
						 << "<div class=\"chart-wrap\">" << render_ping_chart(target) << "</div>"
						 << "<details class=\"attempt-table\"><summary>Attempt details</summary>"
						 << "<div class=\"table-wrap\"><table><thead><tr>"
						 << "<th>#</th><th>Status</th><th>RTT</th><th>TTL</th><th>Timeout</th><th>Code</th>"
						 << "</tr></thead><tbody>";
					for (const auto& attempt : target.attempt_details) {
						html << "<tr>"
							 << "<td>" << attempt.sequence << "</td>"
							 << "<td>" << html_escape(text_or_na(attempt.status)) << "</td>"
							 << "<td>" << html_escape(optional_number_text(attempt.rtt_ms, "{} ms")) << "</td>"
							 << "<td>" << html_escape(ttl_text(attempt.ttl)) << "</td>"
							 << "<td>" << html_escape(bool_text(attempt.timed_out)) << "</td>"
							 << "<td>" << attempt.status_code << "</td>"
							 << "</tr>";
					}
					html << "</tbody></table></div></details></details>";
				}
			}

			html << "</details></section>";
		}

		template<typename T>
		void append_routes_table(std::ostringstream& html, const std::vector<utils::route_entry<T>>& routes, std::string_view title) {
			html << "<details class=\"panel-card nested-panel\"><summary>" << html_escape(title) << "</summary>";
			if (routes.empty()) {
				html << "<div class=\"empty-state\">No routes were captured.</div>";
			} else {
				html << "<div class=\"table-wrap\"><table><thead><tr>"
					 << "<th>Destination</th><th>Next hop</th><th>Interface</th><th>Metric</th>"
					 << "</tr></thead><tbody>";
				for (const auto& route : routes) {
					html << "<tr>"
						 << "<td>" << html_escape(route.destination.to_string()) << "</td>"
						 << "<td>" << html_escape(route.next_hop.to_string()) << "</td>"
						 << "<td>" << html_escape(text_or_na(route.interface)) << "</td>"
						 << "<td>" << route.metric << "</td>"
						 << "</tr>";
				}
				html << "</tbody></table></div>";
			}
			html << "</details>";
		}

		void append_routes(std::ostringstream& html, const checkers::checker_result& result) {
			html << "<section id=\"routes\" class=\"page-section\">"
				 << "<details><summary>Advanced routing</summary>";
			append_routes_table(html, result.route4_table, "IPv4 routes");
			append_routes_table(html, result.route6_table, "IPv6 routes");
			html << "</details></section>";
		}

		std::string render_document(const checkers::checker_result& result) {
			const auto counts = get_severity_counts(result);
			const auto default_gateway_count = std::count_if(result.route4_table.begin(), result.route4_table.end(), [](const auto& route) {
				return route.destination.prefix_length == 0;
			});
			const auto connected_wifi_count = std::count_if(result.wifi_interfaces.begin(), result.wifi_interfaces.end(), [](const auto& wifi) {
				return wifi.connection.connected;
			});
			const auto public_ping_successes = std::count_if(result.ping_targets.begin(), result.ping_targets.end(), [](const auto& target) {
				return target.category == "public" && target.replies > 0;
			});
			const auto public_ping_total = std::count_if(result.ping_targets.begin(), result.ping_targets.end(), [](const auto& target) {
				return target.category == "public";
			});

			std::ostringstream html;
			html << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Netcure Report</title>
<style>
:root {
	color-scheme: light dark;
	--bg: #0f172a;
	--surface: rgba(15, 23, 42, 0.78);
	--surface-strong: rgba(15, 23, 42, 0.92);
	--border: rgba(148, 163, 184, 0.22);
	--text: #e2e8f0;
	--muted: #94a3b8;
	--accent: #38bdf8;
	--error: #f87171;
	--warning: #fbbf24;
	--info: #60a5fa;
	--ok: #34d399;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
	margin: 0;
	font-family: "Segoe UI", system-ui, sans-serif;
	background:
		radial-gradient(circle at top, rgba(56, 189, 248, 0.16), transparent 38%),
		linear-gradient(180deg, #020617 0%, #111827 100%);
	color: var(--text);
}
a { color: var(--accent); }
a:focus-visible,
button:focus-visible,
summary:focus-visible {
	outline: 2px solid var(--accent);
	outline-offset: 3px;
}
.shell {
	max-width: 1280px;
	margin: 0 auto;
	padding: 24px;
}
.hero {
	background: var(--surface);
	border: 1px solid var(--border);
	border-radius: 24px;
	padding: 24px;
	backdrop-filter: blur(10px);
}
.hero h1 {
	margin: 0 0 8px;
	font-size: clamp(1.8rem, 4vw, 2.6rem);
}
.hero p {
	margin: 0;
	color: var(--muted);
}
.topnav {
	position: sticky;
	top: 0;
	z-index: 10;
	display: flex;
	flex-wrap: wrap;
	gap: 8px;
	margin: 16px 0 24px;
	padding: 12px;
	background: rgba(2, 6, 23, 0.8);
	border: 1px solid var(--border);
	border-radius: 16px;
	backdrop-filter: blur(12px);
}
.topnav a {
	display: inline-flex;
	align-items: center;
	min-height: 36px;
	padding: 0 12px;
	border-radius: 999px;
	text-decoration: none;
	background: rgba(148, 163, 184, 0.12);
	color: var(--text);
}
.summary-grid,
.card-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
	gap: 16px;
	margin-top: 20px;
}
.stat-card,
.panel-card {
	background: var(--surface);
	border: 1px solid var(--border);
	border-radius: 20px;
	padding: 18px;
}
.stat-label,
.muted,
.summary-meta {
	color: var(--muted);
}
.stat-value {
	margin-top: 8px;
	font-size: 1.4rem;
	font-weight: 700;
}
.page-section {
	margin-top: 20px;
	scroll-margin-top: 88px;
}
.page-section > details,
.nested-panel {
	background: var(--surface);
	border: 1px solid var(--border);
	border-radius: 20px;
	padding: 0;
	overflow: hidden;
}
details > summary {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: 12px;
	padding: 18px 20px;
	cursor: pointer;
	font-size: 1.05rem;
	font-weight: 600;
	list-style: none;
}
details > summary::-webkit-details-marker { display: none; }
details[open] > summary {
	border-bottom: 1px solid var(--border);
}
.panel-card > h3,
.finding-group h3,
.finding-card h4 {
	margin-top: 0;
}
.toolbar {
	display: flex;
	flex-wrap: wrap;
	gap: 8px;
	padding: 16px 20px 0;
}
.filter-button {
	border: 1px solid var(--border);
	background: rgba(148, 163, 184, 0.1);
	color: var(--text);
	border-radius: 999px;
	padding: 8px 14px;
	min-height: 36px;
	cursor: pointer;
}
.filter-button.active {
	background: rgba(56, 189, 248, 0.2);
	border-color: rgba(56, 189, 248, 0.5);
}
.finding-group,
.page-section > details > .empty-state,
.page-section > details > .card-grid,
.page-section > details > .panel-card,
.page-section > details > .nested-panel,
.page-section > details > .table-wrap,
.page-section > details > .kv-grid,
.page-section > details > .chart-wrap {
	margin: 16px 20px 20px;
}
.finding-card {
	border: 1px solid var(--border);
	border-radius: 16px;
	padding: 16px;
	background: rgba(15, 23, 42, 0.55);
	margin-top: 12px;
}
.finding-title-row {
	display: flex;
	align-items: center;
	gap: 12px;
}
.severity-pill {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	min-width: 72px;
	min-height: 28px;
	padding: 0 10px;
	border-radius: 999px;
	font-size: 0.85rem;
	font-weight: 700;
}
.severity-error {
	border-color: rgba(248, 113, 113, 0.35);
	background: rgba(248, 113, 113, 0.16);
	color: #fecaca;
}
.severity-warning {
	border-color: rgba(251, 191, 36, 0.35);
	background: rgba(251, 191, 36, 0.16);
	color: #fde68a;
}
.severity-info {
	border-color: rgba(96, 165, 250, 0.35);
	background: rgba(96, 165, 250, 0.16);
	color: #bfdbfe;
}
.kv-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 12px;
}
.kv-item {
	background: rgba(15, 23, 42, 0.55);
	border: 1px solid var(--border);
	border-radius: 16px;
	padding: 12px 14px;
}
.kv-label {
	font-size: 0.8rem;
	color: var(--muted);
}
.kv-value {
	margin-top: 6px;
	word-break: break-word;
}
.pill-list {
	display: flex;
	flex-wrap: wrap;
	gap: 8px;
}
.pill {
	display: inline-flex;
	align-items: center;
	min-height: 28px;
	padding: 0 10px;
	border-radius: 999px;
	background: rgba(148, 163, 184, 0.12);
	border: 1px solid var(--border);
}
.table-wrap {
	overflow-x: auto;
}
table {
	width: 100%;
	border-collapse: collapse;
}
th,
td {
	padding: 12px 10px;
	text-align: left;
	border-bottom: 1px solid var(--border);
	font-variant-numeric: tabular-nums;
	white-space: nowrap;
}
th {
	color: var(--muted);
	font-size: 0.85rem;
	font-weight: 600;
}
.empty-state {
	padding: 16px;
	border: 1px dashed var(--border);
	border-radius: 16px;
	color: var(--muted);
}
.chart-wrap {
	padding: 16px;
	border-radius: 16px;
	background: rgba(2, 6, 23, 0.35);
	border: 1px solid var(--border);
}
.ping-chart {
	width: 100%;
	height: auto;
	display: block;
}
.chart-axis {
	stroke: rgba(148, 163, 184, 0.4);
	stroke-width: 1;
}
.chart-line {
	fill: none;
	stroke: var(--accent);
	stroke-width: 3;
	stroke-linejoin: round;
	stroke-linecap: round;
}
.chart-point-success {
	fill: var(--ok);
}
.chart-point-timeout {
	fill: transparent;
	stroke: var(--warning);
	stroke-width: 2;
}
.chart-point-failed {
	fill: transparent;
	stroke: var(--error);
	stroke-width: 2;
}
.chart-label {
	fill: var(--muted);
	font-size: 11px;
	font-family: "Cascadia Mono", Consolas, monospace;
}
.attempt-table {
	margin: 0 20px 20px;
}
.summary-meta {
	font-size: 0.85rem;
	font-weight: 400;
}
@media (max-width: 720px) {
	.shell {
		padding: 16px;
	}
	.hero,
	.panel-card,
	.stat-card {
		border-radius: 18px;
	}
}
</style>
</head>
<body>
<div class="shell">
)";

			html << "<header class=\"hero\">"
				 << "<h1>Netcure report</h1>"
				 << "<p>Generated at " << html_escape(now_text()) << "</p>"
				 << "<div class=\"summary-grid\">";
			append_stat(html, "Verdict", report_verdict(counts));
			append_stat(html, "Errors", std::format("{}", counts.errors));
			append_stat(html, "Warnings", std::format("{}", counts.warnings));
			append_stat(html, "Adapters up", std::format("{}", std::count_if(result.network_interfaces.begin(), result.network_interfaces.end(), [](const auto& adapter) { return adapter.up; })));
			append_stat(html, "Connected Wi-Fi", std::format("{}", connected_wifi_count));
			append_stat(html, "Public reachability", public_ping_total == 0 ? "N/A" : std::format("{}/{}", public_ping_successes, public_ping_total));
			append_stat(html, "Default routes", std::format("{}", default_gateway_count));
			append_stat(html, "Ping targets", std::format("{}", result.ping_targets.size()));
			html << "</div></header>";

			html << "<nav class=\"topnav\" aria-label=\"Report sections\">"
				 << "<a href=\"#findings\">Findings</a>"
				 << "<a href=\"#interfaces\">Adapters</a>"
				 << "<a href=\"#wifi\">Wi-Fi</a>"
				 << "<a href=\"#ping\">Ping</a>"
				 << "<a href=\"#routes\">Routing</a>"
				 << "</nav>";

			append_messages(html, result);
			append_interfaces(html, result);
			append_wifi(html, result);
			append_ping(html, result);
			append_routes(html, result);

			html << R"(
</div>
<script>
document.querySelectorAll(".filter-button").forEach((button) => {
	button.addEventListener("click", () => {
		const filter = button.dataset.filter;
		document.querySelectorAll(".filter-button").forEach((item) => {
			const active = item === button;
			item.classList.toggle("active", active);
			item.setAttribute("aria-pressed", active ? "true" : "false");
		});
		document.querySelectorAll(".finding-card").forEach((card) => {
			const severity = card.dataset.severity.toLowerCase();
			card.hidden = filter !== "all" && severity !== filter;
		});
		document.querySelectorAll(".finding-group").forEach((group) => {
			const visible = Array.from(group.querySelectorAll(".finding-card")).some((card) => !card.hidden);
			group.hidden = !visible;
		});
	});
});
</script>
</body>
</html>
)";
			return html.str();
		}
	}

	std::filesystem::path write_html_report(const checkers::checker_result& result, const std::filesystem::path& output_path) {
		auto resolved_path = output_path.empty()
			? std::filesystem::current_path() / "netcure-report.html"
			: output_path;
		resolved_path = std::filesystem::absolute(resolved_path);

		if (resolved_path.has_parent_path()) {
			std::filesystem::create_directories(resolved_path.parent_path());
		}

		std::ofstream file(resolved_path, std::ios::binary | std::ios::trunc);
		if (!file.is_open()) {
			throw std::runtime_error(std::format("Failed to create report file: {}", resolved_path.string()));
		}

		const auto document = render_document(result);
		file.write("\xEF\xBB\xBF", 3);
		file.write(document.data(), static_cast<std::streamsize>(document.size()));
		file.close();
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
