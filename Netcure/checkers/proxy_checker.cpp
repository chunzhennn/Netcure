#include "pch.h"
#include "proxy_checker.h"
#include <stdexcept>
#include <winhttp.h>
#include <memory>
#include <format>
#include <ranges>
#include <algorithm>
#include <execution>

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
			| std::views::filter([](const utils::route_entry& r) { return r.destination.prefix_length == 0; });
		auto default_entry4 = std::ranges::min_element(default_route4, [](const utils::route_entry& a, const utils::route_entry& b) {
			return a.metric < b.metric;
		});
		if (default_entry4 != default_route4.end()) {
			const auto& interface = std::find(std::execution::par_unseq, ctx.result.network_interfaces.begin(), ctx.result.network_interfaces.end(), [](const utils::network_interface& interface) {
				return interface.ipv4_addresses
			})
		}

	}
}