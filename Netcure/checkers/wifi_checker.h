#pragma once
#ifndef NETCURE_WIFI_CHECKER_H
#define NETCURE_WIFI_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct wifi_checker final : checker {
		~wifi_checker() override = default;
		std::string_view name() const override {
			return "Wi-Fi check";
		}
		bool available(const checker_context& ctx) const override;
		void run(checker_context& ctx) override;
	};
}

#endif // NETCURE_WIFI_CHECKER_H
