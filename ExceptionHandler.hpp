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

#define EH_REPORTSIZE 16384

namespace ExceptionManager
{
	struct EHReport
	{
		char* report_string;
		size_t report_size;
		bool clipped;
	};

	typedef void(*eh_callback)(EHReport);
	struct EHSettings
	{
		std::vector<std::uintptr_t> blacklist_code;
		std::vector<std::string> blacklist_sym;
		std::optional<std::string> prog_name;
		std::uintptr_t prog_base; /* handle */
		std::uintptr_t prog_size;
		eh_callback callback;
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