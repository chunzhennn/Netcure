#pragma once

#ifndef NETCURE_HTML_REPORT_H
#define NETCURE_HTML_REPORT_H

#include <filesystem>
#include <string>
#include <string_view>

#include "../checkers/checker.h"

namespace netcure::report {
	std::string build_report_json(const checkers::checker_result& result);

	std::filesystem::path write_report_json(
		std::string_view report_json,
		const std::filesystem::path& output_path = {}
	);

	std::filesystem::path write_html_report(
		std::string_view report_json,
		const std::filesystem::path& output_path = {}
	);

	bool open_report_in_browser(const std::filesystem::path& report_path);
}

#endif // NETCURE_HTML_REPORT_H
