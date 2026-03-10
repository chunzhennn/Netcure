#include "pch.h"
#include "ping_checker.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

#include <WinSock2.h>
#include <IPExport.h>
#include <Icmpapi.h>
#include <Iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

namespace netcure::checkers {
	namespace {
		constexpr uint32_t ping_attempt_count = 10;
		constexpr DWORD ping_timeout_ms = 1000;
		constexpr DWORD ping_interval_ms = 500;

		struct icmp_handle_deleter {
			void operator()(HANDLE handle) const {
				if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
					IcmpCloseHandle(handle);
				}
			}
		};

		using unique_icmp_handle = std::unique_ptr<void, icmp_handle_deleter>;

		struct ping_attempt_result {
			bool success = false;
			bool timed_out = false;
			uint32_t rtt_ms = 0;
			std::optional<uint8_t> ttl;
			DWORD status = IP_GENERAL_FAILURE;
		};

		struct ping_target_definition {
			std::string category;
			std::string target_name;
			utils::ipv4_addr address;
		};

		unique_icmp_handle _open_icmp_handle() {
			auto handle = IcmpCreateFile();
			if (handle == INVALID_HANDLE_VALUE) {
				throw std::runtime_error(std::format("IcmpCreateFile failed with error code: {}", GetLastError()));
			}
			return unique_icmp_handle(handle);
		}

		IPAddr _to_ipaddr(const utils::ipv4_addr& address) {
			IN_ADDR in_addr{};
			std::memcpy(&in_addr, address.data(), address.size());
			return in_addr.S_un.S_addr;
		}

		std::string _status_to_string(const DWORD status) {
			switch (status) {
			case IP_SUCCESS:
				return "success";
			case IP_REQ_TIMED_OUT:
				return "request timed out";
			case IP_DEST_NET_UNREACHABLE:
				return "network unreachable";
			case IP_DEST_HOST_UNREACHABLE:
				return "host unreachable";
			case IP_DEST_PROT_UNREACHABLE:
				return "protocol unreachable";
			case IP_DEST_PORT_UNREACHABLE:
				return "port unreachable";
			case IP_TTL_EXPIRED_TRANSIT:
				return "ttl expired in transit";
			case IP_GENERAL_FAILURE:
				return "general failure";
			default:
				return std::format("status {}", status);
			}
		}

		ping_attempt_result _ping_once(HANDLE handle, const utils::ipv4_addr& address, const DWORD timeout_ms) {
			constexpr std::array<char, 8> payload{ 'N', 'e', 't', 'c', 'u', 'r', 'e', '\0' };
			std::vector<std::byte> reply_buffer(sizeof(ICMP_ECHO_REPLY) + payload.size() + 16);
			IP_OPTION_INFORMATION options{};
			options.Ttl = 128;

			const auto reply_count = IcmpSendEcho(
				handle,
				_to_ipaddr(address),
				const_cast<char*>(payload.data()),
				static_cast<WORD>(payload.size()),
				&options,
				reply_buffer.data(),
				static_cast<DWORD>(reply_buffer.size()),
				timeout_ms
			);

			auto* reply = reinterpret_cast<ICMP_ECHO_REPLY*>(reply_buffer.data());
			if (reply_count == 0) {
				const auto status = reply->Status != 0 ? reply->Status : GetLastError();
				return ping_attempt_result{
					.success = false,
					.timed_out = status == IP_REQ_TIMED_OUT,
					.rtt_ms = 0,
					.ttl = std::nullopt,
					.status = status
				};
			}

			return ping_attempt_result{
				.success = reply->Status == IP_SUCCESS,
				.timed_out = reply->Status == IP_REQ_TIMED_OUT,
				.rtt_ms = reply->RoundTripTime,
				.ttl = static_cast<uint8_t>(reply->Options.Ttl),
				.status = reply->Status
			};
		}

		ping_target_report _ping_target(HANDLE handle, const ping_target_definition& target, const uint32_t attempts, const DWORD timeout_ms, const DWORD interval_ms) {
			ping_target_report report{};
			report.category = target.category;
			report.target_name = target.target_name;
			report.address = target.address.to_string();
			report.attempts = attempts;
			report.timeout_ms = timeout_ms;
			report.interval_ms = interval_ms;
			report.attempt_details.reserve(attempts);

			std::vector<uint32_t> successful_rtts;
			successful_rtts.reserve(attempts);

			for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
				const auto result = _ping_once(handle, target.address, timeout_ms);
				report.attempt_details.emplace_back(ping_attempt_report{
					.sequence = attempt + 1,
					.success = result.success,
					.timed_out = result.timed_out,
					.rtt_ms = result.success ? std::optional<uint32_t>{ result.rtt_ms } : std::nullopt,
					.ttl = result.ttl,
					.status_code = result.status,
					.status = _status_to_string(result.status)
				});
				if (result.success) {
					++report.replies;
					successful_rtts.emplace_back(result.rtt_ms);
				} else {
					++report.losses;
					if (result.timed_out) {
						++report.timeout_count;
					}
					report.last_error = _status_to_string(result.status);
				}

				if (attempt + 1 < attempts) {
					Sleep(interval_ms);
				}
			}

			report.loss_rate = report.attempts == 0
				? 0.0
				: static_cast<double>(report.losses) * 100.0 / static_cast<double>(report.attempts);

			if (!successful_rtts.empty()) {
				auto [min_it, max_it] = std::minmax_element(successful_rtts.begin(), successful_rtts.end());
				report.min_rtt_ms = *min_it;
				report.max_rtt_ms = *max_it;
				report.avg_rtt_ms = static_cast<double>(std::accumulate(successful_rtts.begin(), successful_rtts.end(), uint64_t{ 0 })) / static_cast<double>(successful_rtts.size());
				if (successful_rtts.size() >= 2) {
					double total_delta = 0.0;
					for (size_t index = 1; index < successful_rtts.size(); ++index) {
						total_delta += std::abs(static_cast<double>(successful_rtts[index]) - static_cast<double>(successful_rtts[index - 1]));
					}
					report.jitter_ms = total_delta / static_cast<double>(successful_rtts.size() - 1);
				} else {
					report.jitter_ms = 0.0;
				}
			}

			return report;
		}

		bool _is_unspecified_gateway(const utils::ipv4_addr& address) {
			return address == utils::ipv4_addr{};
		}

		const utils::network_interface* _find_interface(const checker_context& ctx, const if_id_type interface_id) {
			const auto interface_it = std::find_if(
				ctx.result.network_interfaces.begin(),
				ctx.result.network_interfaces.end(),
				[&](const auto& network_interface) {
					return network_interface.id.Value == interface_id.Value;
				}
			);
			return interface_it == ctx.result.network_interfaces.end() ? nullptr : &*interface_it;
		}

		std::vector<utils::ipv4_addr> _get_default_gateways(const checker_context& ctx) {
			std::vector<utils::ipv4_addr> gateways;
			const utils::route_entry<utils::ipv4_addr>* best_route = nullptr;
			for (const auto& route : ctx.result.route4_table) {
				if (route.destination.prefix_length != 0 || _is_unspecified_gateway(route.next_hop)) {
					continue;
				}

				const auto* network_interface = _find_interface(ctx, route.interface_id);
				if (network_interface == nullptr || !network_interface->up) {
					continue;
				}

				if (
					best_route == nullptr ||
					route.metric < best_route->metric ||
					(route.metric == best_route->metric && !network_interface->is_virtual())
				) {
					best_route = &route;
				}
			}

			if (best_route != nullptr) {
				gateways.emplace_back(best_route->next_hop);
			}

			return gateways;
		}

		std::vector<ping_target_definition> _build_targets(const checker_context& ctx) {
			std::vector<ping_target_definition> targets;
			for (const auto& gateway : _get_default_gateways(ctx)) {
				targets.emplace_back(ping_target_definition{
					.category = "gateway",
					.target_name = std::format("Default gateway {}", gateway.to_string()),
					.address = gateway
				});
			}

			constexpr std::array<std::pair<const char*, const char*>, 3> public_targets{
				std::pair{ "Cloudflare DNS", "1.1.1.1" },
				std::pair{ "Google DNS", "8.8.8.8" },
				std::pair{ "AliDNS", "223.5.5.5" }
			};
			for (const auto& [name, address] : public_targets) {
				targets.emplace_back(ping_target_definition{
					.category = "public",
					.target_name = name,
					.address = utils::ipv4_addr{ address }
				});
			}
			return targets;
		}

		void _append_gateway_messages(checker_context& ctx, const ping_target_report& report) {
			if (report.replies == 0) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::error,
					.title = std::format("Gateway unreachable: {}", report.address),
					.description = "The default gateway did not respond to ICMP echo requests. This usually indicates a local network, adapter, Wi-Fi link, or upstream router issue."
				});
				return;
			}

			if (report.loss_rate > 0.0 || report.jitter_ms.value_or(0.0) >= 10.0 || report.avg_rtt_ms.value_or(0.0) >= 20.0) {
				ctx.result.messages.emplace_back(checker_message{
					.level = report.loss_rate >= 25.0 ? severity::error : severity::warning,
					.title = std::format("Gateway ping is unstable: {}", report.address),
					.description = std::format(
						"Gateway ping shows {:.1f}% packet loss, average latency {:.1f} ms, jitter {:.1f} ms.",
						report.loss_rate,
						report.avg_rtt_ms.value_or(0.0),
						report.jitter_ms.value_or(0.0)
					)
				});
			}
		}

		void _append_public_messages(checker_context& ctx, const std::vector<ping_target_report>& reports) {
			const auto public_begin = reports.begin();
			const auto public_end = reports.end();
			const auto failed_count = static_cast<size_t>(std::count_if(public_begin, public_end, [](const auto& report) {
				return report.category == "public" && report.replies == 0;
			}));

			for (const auto& report : reports) {
				if (report.category != "public") {
					continue;
				}

				if (report.replies == 0) {
					continue;
				}

				if (report.loss_rate >= 20.0 || report.jitter_ms.value_or(0.0) >= 40.0 || report.avg_rtt_ms.value_or(0.0) >= 150.0) {
					ctx.result.messages.emplace_back(checker_message{
						.level = severity::warning,
						.title = std::format("Public ping is unstable: {}", report.target_name),
						.description = std::format(
							"Public target {} ({}) shows {:.1f}% packet loss, average latency {:.1f} ms, jitter {:.1f} ms.",
							report.target_name,
							report.address,
							report.loss_rate,
							report.avg_rtt_ms.value_or(0.0),
							report.jitter_ms.value_or(0.0)
						)
					});
				}
			}

			if (failed_count == 3) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::error,
					.title = "All public ping targets are unreachable",
					.description = "The local gateway may still be reachable, but all tested public IPv4 targets failed. This usually indicates upstream Internet connectivity issues, routing problems, or ICMP being blocked outside the local network."
				});
			} else if (failed_count > 0) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::warning,
					.title = "Some public ping targets are unreachable",
					.description = std::format("{} public ping target(s) did not respond. The issue may be partial upstream reachability or ICMP filtering.", failed_count)
				});
			}
		}
	}

	bool ping_checker::available(const checker_context& ctx) const {
		return !ctx.result.route4_table.empty();
	}

	void ping_checker::run(checker_context& ctx) {
		const auto targets = _build_targets(ctx);
		if (targets.empty()) {
			ctx.result.messages.emplace_back(checker_message{
				.level = severity::warning,
				.title = "No ping targets available",
				.description = "No IPv4 default gateway was found, so only route-derived ICMP diagnostics were skipped."
			});
			return;
		}

		auto icmp_handle = _open_icmp_handle();
		std::vector<ping_target_report> current_reports;
		current_reports.reserve(targets.size());

		for (const auto& target : targets) {
			auto report = _ping_target(icmp_handle.get(), target, ping_attempt_count, ping_timeout_ms, ping_interval_ms);
			ctx.result.ping_targets.emplace_back(report);
			current_reports.emplace_back(std::move(report));
		}

		for (const auto& report : current_reports) {
			if (report.category == "gateway") {
				_append_gateway_messages(ctx, report);
			}
		}
		_append_public_messages(ctx, current_reports);
	}
}
