#pragma once
#ifndef NETCURE_ROUTE_CHECKER_H
#define NETCURE_ROUTE_CHECKER_H

#include "checker.h"
#include <algorithm>
#include <execution>

namespace netcure::checkers {
	struct route_checker final : checker {
		virtual ~route_checker() = default;
		std::string_view name() const override {
			return "Route check";
		}
		virtual bool available(const checker_context& ctx) const {
			// If there is no network interface that is up, we cannot check routes
			return std::any_of(
				std::execution::par_unseq,
				std::begin(ctx.result.network_interfaces),
				std::end(ctx.result.network_interfaces),
				[](const utils::network_interface& iface) {
					return iface.up;
				}
			);
		}

		virtual void run(checker_context& ctx);
	};
}

#endif // NETCURE_ROUTE_CHECKER_H