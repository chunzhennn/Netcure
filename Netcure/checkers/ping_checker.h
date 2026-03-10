#pragma once
#ifndef NETCURE_PING_CHECKER_H
#define NETCURE_PING_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct ping_checker final : checker {
		~ping_checker() override = default;
		bool available(const checker_context& ctx) const override;
		void run(checker_context& ctx) override;
	};
}

#endif // NETCURE_PING_CHECKER_H
