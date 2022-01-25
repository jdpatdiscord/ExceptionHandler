#include "ExceptionHandler.hpp"


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
};