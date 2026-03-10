#include "pch.h"
#include "route_checker.h"
#include <memory>
#include <algorithm>
#include <execution>
#include <string>
#include <unordered_map>

#include "../utils.h"
#include <winsock2.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

namespace netcure::checkers {
	namespace {
		auto _get_route_table(ADDRESS_FAMILY family = AF_UNSPEC) {
			struct route_table_deleter {
				void operator()(MIB_IPFORWARD_TABLE2* ptr) const {
					FreeMibTable(ptr);
				}
			};
			MIB_IPFORWARD_TABLE2* p_table = nullptr;
			auto rc = GetIpForwardTable2(family, &p_table);
			if (rc != NO_ERROR) {
				throw std::runtime_error(std::format("GetIpForwardTable2 failed with error code: {}", rc));
			}
			return std::unique_ptr<MIB_IPFORWARD_TABLE2, route_table_deleter>(p_table);
		}

		std::string _get_interface_alias(const NET_LUID* luid) {
			int buflen = 128;
			
			for (int i = 0; i < 3; i++) { // 3 tries max
				auto* str = new wchar_t[buflen];
				auto rc = ConvertInterfaceLuidToAlias(luid, str, buflen);
				if (rc == NO_ERROR) {
					std::wstring alias(str);
					delete[] str;
					return utils::to_string(alias);
				} else if (rc == ERROR_INSUFFICIENT_BUFFER) {
					delete[] str;
					buflen *= 2; // Double the buffer size
				} else {
					delete[] str;
					throw std::runtime_error(std::format("ConvertInterfaceLuidToAlias failed with error code: {}", rc));
				}
			}
			throw std::runtime_error("Failed to allocate memory for ConvertInterfaceLuidToAlias: too much memory requested");
		}

		ULONG _get_effective_route_metric(const ADDRESS_FAMILY family, const MIB_IPFORWARD_ROW2& route_entry, std::unordered_map<ULONGLONG, ULONG>& interface_metric_cache) {
			const auto interface_key = route_entry.InterfaceLuid.Value;
			if (const auto cached = interface_metric_cache.find(interface_key); cached != interface_metric_cache.end()) {
				return route_entry.Metric + cached->second;
			}

			MIB_IPINTERFACE_ROW interface_row{};
			InitializeIpInterfaceEntry(&interface_row);
			interface_row.Family = family;
			interface_row.InterfaceLuid = route_entry.InterfaceLuid;

			const auto rc = GetIpInterfaceEntry(&interface_row);
			if (rc != NO_ERROR) {
				throw std::runtime_error(std::format("GetIpInterfaceEntry failed with error code: {}", rc));
			}

			interface_metric_cache.emplace(interface_key, interface_row.Metric);
			return route_entry.Metric + interface_row.Metric;
		}
	}
	void route_checker::run(checker_context& ctx) {
		auto v4table = _get_route_table(AF_INET);
		auto v6table = _get_route_table(AF_INET6);
		std::unordered_map<ULONGLONG, ULONG> v4_interface_metric_cache;
		std::unordered_map<ULONGLONG, ULONG> v6_interface_metric_cache;

		for (ULONG i = 0; i < v4table->NumEntries; i++) {
			const auto* entry = &v4table->Table[i];
			char addr_buf[64] = { 0 };
			auto v4dest = utils::ipv4_addr{ inet_ntop(AF_INET, &entry->DestinationPrefix.Prefix.Ipv4.sin_addr, addr_buf, sizeof(addr_buf)) };
			auto destination = utils::cidr<utils::ipv4_addr>{std::move(v4dest), entry->DestinationPrefix.PrefixLength};
			auto v4nexthop = utils::ipv4_addr{ inet_ntop(AF_INET, &entry->NextHop.Ipv4.sin_addr, addr_buf, sizeof(addr_buf)) };
			ctx.result.route4_table.emplace_back(utils::route_entry<utils::ipv4_addr>{
				.destination = std::move(destination),
				.next_hop = std::move(v4nexthop),
				.interface = _get_interface_alias(&entry->InterfaceLuid),
             .interface_id = entry->InterfaceLuid,
				.metric = _get_effective_route_metric(AF_INET, *entry, v4_interface_metric_cache)
			});
		}

		for (ULONG i = 0; i < v6table->NumEntries; i++) {
			const auto* entry = &v6table->Table[i];
			char addr_buf[64] = { 0 };
			auto v6dest = utils::ipv6_addr{ inet_ntop(AF_INET6, &entry->DestinationPrefix.Prefix.Ipv6.sin6_addr, addr_buf, sizeof(addr_buf)) };
			auto destination = utils::cidr<utils::ipv6_addr>{ std::move(v6dest), entry->DestinationPrefix.PrefixLength };
			auto v6nexthop = utils::ipv6_addr{ inet_ntop(AF_INET6, &entry->NextHop.Ipv6.sin6_addr, addr_buf, sizeof(addr_buf)) };
			ctx.result.route6_table.emplace_back(utils::route_entry<utils::ipv6_addr>{
				.destination = std::move(destination),
				.next_hop =  std::move(v6nexthop),
				.interface = _get_interface_alias(&entry->InterfaceLuid),
				.interface_id = entry->InterfaceLuid,
				.metric = _get_effective_route_metric(AF_INET6, *entry, v6_interface_metric_cache)
			});
		}

		if (!std::any_of(std::execution::par_unseq, ctx.result.route4_table.begin(), ctx.result.route4_table.end(), [](const auto& entry) {
			return entry.destination.prefix_length == 0;
		})) {
			ctx.result.messages.emplace_back(checker_message{
				.level = severity::error,
				.title = "Missing IPv4 default route",
				.description = "You don't have an IPv4 default route, this may indicate not having an IPv4 address in your network interface. This may be caused by DHCP service error, network configuration error, or network card failure."
			});
		}

		if (!std::any_of(std::execution::par_unseq, ctx.result.route6_table.begin(), ctx.result.route6_table.end(), [](const auto& entry) {
			return entry.destination.prefix_length == 0;
		})) {
			ctx.result.messages.emplace_back(checker_message{
				.level = severity::warning,
				.title = "Missing IPv6 default route",
				.description = "You don't have an IPv6 default route, this may indicate not having an IPv6 address in your network interface. This is possibly caused by network configuration error or environment limitations."
			});
		}
	}
}