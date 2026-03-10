#pragma once
#ifndef NETCURE_ADAPTER_CHECKER_H
#define NETCURE_ADAPTER_CHECKER_H

#include "checker.h"

namespace netcure::checkers {
	struct adapter_checker final: checker {
		virtual ~adapter_checker() = default;

		std::string_view name() const override {
			return "Adapter check";
		}

		virtual bool available(const checker_context&) const {
			return true;
		}

		virtual void run(checker_context&);
	};
}

#endif // NETCURE_ADAPTER_CHECKER_H