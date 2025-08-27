#pragma once
#ifndef NETCURE_CHECKER_H
#define NETCURE_CHECKER_H

#include<vector>
#include<string>
#include<map>
#include<variant>
#include<utility>
#include<iostream>
#include<concepts>

#include "../utils.h"

namespace netcure::checkers {

	enum class severity {
		info,
		warning,
		error,
	};

	struct checker_message {
		severity level;
		std::string title;
		std::string description;
	};

	struct checker_result {
		std::vector<utils::network_interface> network_interfaces;
		std::vector<checker_message> messages;
		std::vector<utils::route_entry<utils::ipv4_addr>> route4_table;
		std::vector<utils::route_entry<utils::ipv6_addr>> route6_table;
	};

	struct checker_context {
		bool has_wireless_adapter = false;
		int active_adapter_count = 0;
		// All report-related data is stored in result
		checker_result result;
	};

	struct checker {
		virtual ~checker() = default;
		virtual bool available(const checker_context&) const = 0;
		virtual void run(checker_context&) = 0;
	};

	template<typename... Ts>
	requires (std::derived_from<Ts, checker> && ...)
	checker_result run_checkers() {
		checker_context ctx;
		// Create a vector of checkers
		std::vector<std::unique_ptr<checker>> checkers;
		(checkers.emplace_back(std::make_unique<Ts>()), ...);

		// Run each checker
		for (auto& c : checkers) {
			if (c->available(ctx)) {
				try {
					c->run(ctx);
				}
				catch (const std::exception& e) {
					ctx.result.messages.emplace_back(
						checker_message{
							severity::error,
							"Checker Error",
							std::format("An error occurred while running {}: {}", typeid(*c).name(), e.what())
						}
					);
					std::cerr << ctx.result.messages.back().description << std::endl;
				}
			}
		}
		return std::move(ctx.result);
	}
}

#endif // NETCURE_CHECKER_H