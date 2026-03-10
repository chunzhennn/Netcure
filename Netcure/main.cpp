#include "pch.h"
#include "checkers/adapter_checker.h"
#include "checkers/wifi_checker.h"
#include "checkers/route_checker.h"
#include "checkers/ping_checker.h"
#include "checkers/proxy_checker.h"
#include "report/html_report.h"

using namespace netcure::checkers;
int main()
{
    SetConsoleOutputCP(CP_UTF8);
    const auto result = run_checkers<adapter_checker, wifi_checker, route_checker, ping_checker, proxy_checker>();
    std::cout << "Generating HTML report..." << std::endl;
    const auto report_path = netcure::report::write_html_report(result);
    std::cout << "Generated report: " << report_path.string() << std::endl;
    std::cout << "Opening report in your default browser..." << std::endl;
    if (!netcure::report::open_report_in_browser(report_path)) {
        std::cerr << "Unable to open the HTML report automatically. Open it manually from: " << report_path.string() << std::endl;
    }
    return 0;
}
