#pragma once
#ifndef NETCURE_PROXY_CHECKER_H
#define NETCURE_PROXY_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct proxy_checker final : checker {
		virtual ~proxy_checker() = default;

		virtual bool available(const checker_context& ctx) const {
			return !(ctx.result.route4_table.empty() && ctx.result.route6_table.empty());
		}

		virtual void run(checker_context&);
	};
}

#endif // NETCURE_PROXY_CHECKER_H