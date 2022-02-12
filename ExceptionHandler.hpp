#pragma once
#ifndef _EH32_INCLUDE
#define _EH32_INCLUDE

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include <memory>

#if !defined(XSTATE_AVX512_KMASK) && !defined(XSTATE_AVX512_ZMM_H) && !defined(XSTATE_AVX512_ZMM)
#define XSTATE_AVX512_KMASK                 (5)
#define XSTATE_AVX512_ZMM_H                 (6)
#define XSTATE_AVX512_ZMM                   (7)
#endif

#ifndef XSTATE_MASK_AVX512
#define XSTATE_MASK_AVX512                  ((1ull << (XSTATE_AVX512_KMASK)) | \
                                             (1ull << (XSTATE_AVX512_ZMM_H)) | \
                                             (1ull << (XSTATE_AVX512_ZMM)))
#endif

#define EH_REPORTSIZE 16384

#if defined(_M_ARM64)
static const char* const Arm64IndexToNameMap[] = {
	"X0",
	"X1",
	"X2",
	"X3",
	"X4",
	"X5",
	"X6",
	"X7",
	"X8",
	"X9",
	"X10",
	"X11",
	"X12",
	"X13",
	"X14",
	"X15",
	"X16",
	"X17",
	"X18",
	"X19",
	"X20",
	"X21",
	"X22",
	"X23",
	"X24",
	"X25",
	"X26",
	"X27",
	"X28",
	"Fp",
	"Lr",
};
#endif

namespace PeParser
{
	std::uintptr_t get_image_base(std::uintptr_t module_base);
}

std::string SStr_format(const char* fmt, ...);

#define EH_STRREG(EHREG) {#EHREG, EHREG, sizeof(decltype(EHREG))}

namespace ExceptionManager
{
	typedef std::tuple<std::string, std::uint64_t, std::size_t> EHRegister;

	struct EHStackWalkLine
	{
		uintptr_t address = NULL;
		uintptr_t module_base_address = NULL;
		std::string module_name = "";
		std::string source_file_name = "";
		std::string function_symbol = "";
		std::int32_t line = -1;
	};

	struct EHCompiledReport
	{
		std::vector<EHStackWalkLine> complete_callstack;
		std::vector<EHRegister> register_list;
		std::uint32_t eh_exception_code = NULL;
		std::uintptr_t eh_fault_address = NULL;
		//std::string eh_psuedo_name = "";
		std::string eh_cpp_exception_symbol = "";
		std::string eh_cpp_exception_message = "";

		bool should_ignore = false;
	};

	struct EHFinishedReport
	{
		char* report_string;
		size_t report_size;
		bool clipped;
		bool should_free;

		EHFinishedReport(char* report_string, size_t report_size, bool clipped, bool should_free)
			: report_string(report_string), report_size(report_size), clipped(clipped), should_free(should_free) { }

		EHFinishedReport()
		{
			memset(this, 0, sizeof(EHFinishedReport));
		}
	};

	typedef void(*eh_receiver_callback)(EHFinishedReport);
	typedef EHFinishedReport(*eh_processor_callback)(EHCompiledReport);

	struct EHSettings
	{
		std::vector<std::uintptr_t> blacklist_code;
		std::vector<std::string> blacklist_sym;
		std::string prog_name = "";
		uintptr_t prog_base; /* handle */
		uintptr_t prog_size; 
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

	EHFinishedReport DefaultProcessor(EHCompiledReport report);
	void DefaultHandler(EHFinishedReport report);

	std::string getBack(const std::string& s, char delim);
	bool IsXStatePresent();
	std::string ResolveModuleFromAddress(DWORD Address);
	EHCompiledReport GenerateReport(PEXCEPTION_POINTERS pExceptionRecord);
	PCHAR GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionRecord);
	PCHAR GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord);
	BOOL ProcessException(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
};

#endif