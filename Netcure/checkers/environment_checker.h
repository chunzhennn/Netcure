#pragma once
#ifndef NETCURE_ENVIRONMENT_CHECKER_H
#define NETCURE_ENVIRONMENT_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct environment_checker final : checker {
		~environment_checker() override = default;
		std::string_view name() const override {
			return "Environment check";
		}
		bool available(const checker_context&) const override {
			return true;
		}
		void run(checker_context& ctx) override;
	};
}

#endif // NETCURE_ENVIRONMENT_CHECKER_H
