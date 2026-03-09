#include "pch.h"
#include "proxy_checker.h"
#include <stdexcept>
#include <winhttp.h>
#include <memory>
#include <format>
#include <ranges>
#include <algorithm>
#include <execution>
#include <cstring>

#pragma comment(lib, "winhttp.lib")

namespace netcure::checkers {
	void proxy_checker::run(checker_context& ctx) {
		// check HTTP proxy
		auto config = std::make_unique<WINHTTP_CURRENT_USER_IE_PROXY_CONFIG>();
		if (!WinHttpGetIEProxyConfigForCurrentUser(config.get())) {
			throw std::runtime_error(std::format("WinHttpGetIEProxyConfigForCurrentUser failed: {}", GetLastError()));
		}
		
		if (config->lpszProxy) {
			// HTTP Proxy Enabled
			ctx.result.messages.emplace_back(checker_message{
				.level = severity::warning,
				.title = "HTTP Proxy Detected",
				.description = "You have enabled HTTP proxy, which would lead to inaccurate results. Try disabling it in Windows settings."
			});
		}

        // check TUN proxy
		auto default_route4 = ctx.result.route4_table
			| std::views::filter([](const utils::route_entry<utils::ipv4_addr>& r) { return r.destination.prefix_length == 0; });
		auto default_entry4 = std::ranges::min_element(default_route4, [](const auto& a, const auto& b) {
			return a.metric < b.metric;
		});
		if (default_entry4 != default_route4.end()) {
          const auto iface = std::find_if(ctx.result.network_interfaces.begin(), ctx.result.network_interfaces.end(), [&](const auto& iface) {
				return std::memcmp(&iface.id, &default_entry4->interface_id, sizeof(if_id_type)) == 0;
			});
			if (iface == ctx.result.network_interfaces.end()) {
				throw std::runtime_error("Your default route points to a non-existant network interface");
			}
			if (iface->is_virtual()) {
				ctx.result.messages.emplace_back(checker_message{
					.level = severity::warning,
					.title = "TUN Proxy Detected",
					.description = "You have enabled TUN proxy, results could be terrible wrong!"
				});
			}
		}

	}
}