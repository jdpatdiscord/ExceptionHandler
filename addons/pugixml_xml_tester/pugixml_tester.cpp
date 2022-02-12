#include "pugixml_tester.hpp"

struct xml_string_writer : pugi::xml_writer
{
	std::string result;

	virtual void write(const void* data, size_t size)
	{
		result.append(static_cast<const char*>(data), size);
	}
};

std::string node_to_string(pugi::xml_node node)
{
	xml_string_writer writer;
	node.print(writer);

	return writer.result;
}

ExceptionManager::EHFinishedReport xml_reporter(ExceptionManager::EHCompiledReport report)
{
	pugi::xml_document ehdoc;

	pugi::xml_node general = ehdoc.append_child("exception_info");
	general.append_attribute("exception_code").set_value(report.eh_exception_code);
	general.append_attribute("fault_address").set_value(report.eh_fault_address);

	if (report.eh_exception_code == 0xE06D7363)
	{
		pugi::xml_node x_cpp_info = general.append_child("cpp_exception");
		x_cpp_info.append_attribute("message").set_value(report.eh_cpp_exception_message.c_str());
		x_cpp_info.append_attribute("symbol").set_value(report.eh_cpp_exception_symbol.c_str());
	}

	pugi::xml_node x_registers = ehdoc.append_child("registers");
	for (auto& reg : report.register_list)
	{
		auto reg_name = std::get<0>(reg);
		auto reg_value = std::get<1>(reg);
		auto reg_size = std::get<2>(reg);

		pugi::xml_node x_reg = x_registers.append_child(reg_name.c_str());
		x_reg.append_attribute("value").set_value(reg_value);
		x_reg.append_attribute("size").set_value(reg_size);
	}

	pugi::xml_node x_callstack = ehdoc.append_child("callstack");
	unsigned calln = 0;
	for (auto& callo : report.complete_callstack)
	{
		pugi::xml_node x_call = x_callstack.append_child("call");
		x_call.append_attribute("number").set_value(calln);
		if (callo.function_symbol != "")
			x_call.append_attribute("function_symbol").set_value(callo.function_symbol.c_str());
		if (callo.line != -1)
			x_call.append_attribute("line").set_value(callo.line);
		if (callo.module_base_address != NULL)
			x_call.append_attribute("module_base").set_value(callo.module_base_address);
		if (callo.module_name != "")
			x_call.append_attribute("module_name").set_value(callo.module_name.c_str());
		if (callo.source_file_name != "")
			x_call.append_attribute("source_file_name").set_value(callo.source_file_name.c_str());

		++calln;
	}
	
	std::string res = node_to_string(ehdoc);

	char* report_buf = (char*)malloc(res.size() + 1);
	memset(report_buf, 0, res.size() + 1);
	memcpy(report_buf, res.c_str(), res.size());

	return { report_buf, res.size(), false, true };
}

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
		xml_reporter,                                  /* report parser: how to generate the finished report */
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