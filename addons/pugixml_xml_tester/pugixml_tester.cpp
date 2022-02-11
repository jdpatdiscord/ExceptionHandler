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
	pugi::xml_node registers = ehdoc.append_child("registers");

	for (auto& reg : report.register_list)
	{
		auto reg_name = std::get<0>(reg);
		auto reg_value = std::get<1>(reg);
		auto reg_size = std::get<2>(reg);

		pugi::xml_node xmlreg = registers.append_child(reg_name.c_str());
		xmlreg.append_attribute("value").set_value(reg_value);
		xmlreg.append_attribute("size").set_value(reg_size);
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
		ExceptionManager::DefaultProcessor,            /* report parser: how to generate the finished report */
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