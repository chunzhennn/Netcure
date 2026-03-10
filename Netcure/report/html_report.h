#pragma once

#ifndef NETCURE_HTML_REPORT_H
#define NETCURE_HTML_REPORT_H

#include <filesystem>

#include "../checkers/checker.h"

namespace netcure::report {
	std::filesystem::path write_html_report(
		const checkers::checker_result& result,
		const std::filesystem::path& output_path = {}
	);

	bool open_report_in_browser(const std::filesystem::path& report_path);
}

#endif // NETCURE_HTML_REPORT_H
