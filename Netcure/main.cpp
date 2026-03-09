#include "pch.h"
#include "checkers/adapter_checker.h"
#include "checkers/wifi_checker.h"
#include "checkers/route_checker.h"
#include "checkers/proxy_checker.h"

using namespace netcure::checkers;
int main()
{
    SetConsoleOutputCP(CP_UTF8);
    auto _ = run_checkers<adapter_checker, wifi_checker, route_checker, proxy_checker>();
    return 0;
}
