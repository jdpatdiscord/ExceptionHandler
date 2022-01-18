#pragma once
#ifndef _EH32_INCLUDE
#define _EH32_INCLUDE

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <optional>
#include <map>

#define EH_REPORTSIZE 16384

namespace PeParser
{
	std::uintptr_t get_image_base(std::uintptr_t module_base);
}

namespace ExceptionManager
{
	typedef std::pair<std::string, std::uintptr_t> EHRegister;

	struct EHStackWalkLine
	{
		std::uintptr_t module_base_address;
		std::uintptr_t address;
		std::string module_name;
		std::string source_file_name;
		std::int32_t line;
	};

	struct EHUnfinishedReport
	{
		std::vector<EHStackWalkLine> complete_callstack;
		std::vector<EHRegister> register_list;
		std::uint32_t eh_exception_code;
		std::string eh_cpp_exception_name;
		std::string eh_cpp_exception_message;
		std::string eh_psuedo_name;
	};

	struct EHCompiledReport
	{
		char* report_string;
		size_t report_size;
		bool clipped;
	};

	typedef void(*eh_receiver_callback)(EHCompiledReport);
	typedef std::string(*eh_processor_callback)(EHUnfinishedReport);

	struct EHSettings
	{
		std::vector<std::uintptr_t> blacklist_code;
		std::vector<std::string> blacklist_sym;
		std::optional<std::string> prog_name;
		std::uintptr_t prog_base; /* handle */
		std::uintptr_t prog_size; 
		eh_receiver_callback recv_callback;
		eh_processor_callback proc_callback;
		char* report_dst;
		size_t report_dst_size;
		bool is_prog_dll;
		bool use_seh;
		bool use_veh;
	};

	extern EHSettings g_ehsettings;
	extern char g_ehreportbuffer[EH_REPORTSIZE];

	void Init(EHSettings* settings);

	std::string getBack(const std::string& s, char delim);
	std::string ResolveModuleFromAddress(DWORD Address);
	std::string StackWalkReport(PEXCEPTION_POINTERS pExceptionRecord);
	PCHAR GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionRecord);
	PCHAR GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord);
	BOOL ExceptionNotify(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
};

#endif