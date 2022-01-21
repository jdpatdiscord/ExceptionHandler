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

	//*(int*)(0) = 0;
	throw std::runtime_error("This is a test");

	return 0;
};