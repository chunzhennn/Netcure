#pragma once
#ifndef NETCURE_PROXY_CHECKER_H
#define NETCURE_PROXY_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct proxy_checker final : checker {
		virtual ~proxy_checker() = default;

		std::string_view name() const override {
			return "Proxy check";
		}

		virtual bool available(const checker_context& ctx) const {
			return !(ctx.result.route4_table.empty() && ctx.result.route6_table.empty());
		}

		virtual void run(checker_context&);
	};
}

#endif // NETCURE_PROXY_CHECKER_H