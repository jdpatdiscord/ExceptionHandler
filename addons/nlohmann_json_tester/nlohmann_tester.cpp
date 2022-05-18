#include "nlohmann_tester.hpp"

ExceptionManager::EHFinishedReport json_reporter(ExceptionManager::EHCompiledReport report)
{
	nlohmann::json ehjson;

	ehjson["exception_code"] = report.eh_exception_code;
	ehjson["fault_address"] = report.eh_fault_address;
	if (report.eh_exception_code == 0xE06D7363)
	{
		ehjson["cpp_exception_message"] = report.eh_cpp_exception_message;
		ehjson["cpp_exception_symbol"] = report.eh_cpp_exception_symbol;
	}

	ehjson["registers"] = {};

	for (auto& reg : report.register_list)
	{
		ehjson["registers"][reg.reg_name] = {};
		ehjson["registers"][reg.reg_name].emplace("value", reg.reg_value);
		ehjson["registers"][reg.reg_name].emplace("size", reg.reg_size);
	}

	ehjson["callstack"] = {};

	unsigned calln = 0;
	for (auto& callo : report.complete_callstack)
	{
		std::string call_name = std::string("call_") + std::to_string(calln);
		ehjson["callstack"][call_name] = {};
		ehjson["callstack"][call_name].emplace("address", callo.address);
		ehjson["callstack"][call_name].emplace("number", calln);
		if (callo.function_symbol != "") 
			ehjson["callstack"][call_name].emplace("function_symbol", callo.function_symbol);
		if (callo.line != -1)
			ehjson["callstack"][call_name].emplace("line", callo.line);
		if (callo.module_base_address != NULL)
			ehjson["callstack"][call_name].emplace("module_base", callo.module_base_address);
		if (callo.module_name != "")
			ehjson["callstack"][call_name].emplace("module_name", callo.module_name);
		if (callo.source_file_name != "")
			ehjson["callstack"][call_name].emplace("source_file_name", callo.source_file_name);

		++calln;
	}

	std::string res = ehjson.dump(4);

	char* report_buf = (char*)malloc(res.size() + 1);
	memset(report_buf, 0, res.size() + 1);
	memcpy(report_buf, res.c_str(), res.size());

	return ExceptionManager::EHFinishedReport( report_buf, res.size(), false, true );
}

#ifndef _WINDLL
int main(int argc, char* argv[])
{
	ExceptionManager::EHSettings settings = {
		{ 0x80000004,
		  0x80000006,
		  0x40010006,
		  0x406D1388 },                                /* blacklisted codes*/
		{ },                                           /* blacklisted symbols */
		argv[0],                                       /* program name std::optional */
		(std::uintptr_t)GetModuleHandle(NULL),         /* base */
		NULL,                                          /* attempts to get prog size for you if NULL */
		ExceptionManager::DefaultHandler,              /* report handler: what to do with the finished report */
		json_reporter,                                 /* report parser: how to generate the finished report */
		NULL,                                          /* inbuilt report location */
		NULL,                                          /* inbuilt report size */
		false,                                         /* is this a DLL?: */
		true,                                          /* use SEH?: */
		false,                                         /* use VEH?: */
	};

	ExceptionManager::Init(&settings);

#if defined(_M_X64) || defined(_M_ARM64)
	//*(uint64_t*)(0xABABCDCDEFEF2244) = 0xFFEEDDCCBBAA0022;
#elif defined(_M_IX86)
	//*(uint64_t*)(0xAABBCCDD) = 0xEEFF2244;
#endif
	throw std::runtime_error("This is a test (runtime_error)");
	//throw std::invalid_argument("This is a test (invalid_argument)");

	return 0;
}
#else
BOOL APIENTRY DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);

		ExceptionManager::EHSettings settings = {
			{ 0x80000004,
			  0x80000006,
			  0x40010006,
			  0x406D1388 },                                /* blacklisted codes*/
			{ },                                           /* blacklisted symbols */
			"Lol",                                         /* program name std::optional */
			(std::uintptr_t)GetModuleHandle(NULL),         /* base */
			NULL,                                          /* attempts to get prog size for you if NULL */
			ExceptionManager::DefaultHandler,              /* report handler: what to do with the finished report */
			json_reporter,                                 /* report parser: how to generate the finished report */
			NULL,                                          /* inbuilt report location */
			NULL,                                          /* inbuilt report size */
			true ,                                         /* is this a DLL?: */
			true,                                          /* use SEH?: */
			false,                                         /* use VEH?: */
		};

		ExceptionManager::Init(&settings);
	}
	return TRUE;
}
#endif