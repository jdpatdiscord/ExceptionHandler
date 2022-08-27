#include "./ExceptionHandler.hpp"

typedef DWORD64(WINAPI* PGETENABLEDXSTATEFEATURES)();
typedef PVOID(WINAPI* LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);

PGETENABLEDXSTATEFEATURES _GetEnabledXStateFeatures = NULL;
LOCATEXSTATEFEATURE _LocateXStateFeature = NULL;

std::uintptr_t PeParser::get_image_base(std::uintptr_t module_base)
{
	PIMAGE_DOS_HEADER p_dos_hdr = (PIMAGE_DOS_HEADER)module_base;
	if (p_dos_hdr->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS p_nt_hdr = (PIMAGE_NT_HEADERS)((PCHAR)p_dos_hdr + p_dos_hdr->e_lfanew);
		if (p_nt_hdr->Signature == IMAGE_NT_SIGNATURE)
		{
			return p_nt_hdr->OptionalHeader.ImageBase;
		}
	}
	return NULL;
}

std::string SStr_format(const char* fmt, ...)
{
	char buf[256];

	va_list args;
	va_start(args, fmt);
	const auto r = std::vsnprintf(buf, sizeof buf, fmt, args);
	va_end(args);

	if (r < 0)
		// conversion failed
		return {};

	const size_t len = r;
	if (len < sizeof buf)
		// we fit in the buffer
		return { buf, len };

#if __cplusplus >= 201703L
	// C++17: Create a string and write to its underlying array
	std::string s(len, '\0');
	va_start(args, fmt);
	std::vsnprintf(s.data(), len + 1, fmt, args);
	va_end(args);

	return s;
#else
	// C++11 or C++14: We need to allocate scratch memory
	auto vbuf = std::unique_ptr<char[]>(new char[len + 1]);
	va_start(args, fmt);
	std::vsnprintf(vbuf.get(), len + 1, fmt, args);
	va_end(args);

	return { vbuf.get(), len };
#endif
}

ExceptionManager::EHSettings ExceptionManager::g_ehsettings;
char ExceptionManager::g_ehreportbuffer[EH_REPORTSIZE];

std::string ExceptionManager::getBack(const std::string& s, char delim) {
	std::stringstream ss(s);
	std::string item;

	while (std::getline(ss, item, delim));

	return item;
}

bool ExceptionManager::IsXStatePresent()
{
	return (_GetEnabledXStateFeatures != NULL && _LocateXStateFeature != NULL);
}

ExceptionManager::EHFinishedReport ExceptionManager::DefaultProcessor(ExceptionManager::EHCompiledReport report)
{
	std::string string_trace = "";
	std::string string_register_list = "";

	for (EHStackWalkLine& stack_line : report.complete_callstack)
	{
		std::string string_address = SStr_format("0x%p", stack_line.module_base_address);
		std::string string_module_name = stack_line.module_name != "" ? stack_line.module_name.c_str() : string_address.c_str();

		std::string string_line = SStr_format(
			"Addr: (%s) + 0x%p, Base: 0x%p, Line: %i, Func: %s, File: %s\n",
			string_module_name.c_str(),
			stack_line.address,
			stack_line.module_base_address,
			stack_line.line != 0 ? stack_line.line : -1,
			stack_line.function_symbol != "" ? stack_line.function_symbol.c_str() : "NoFunc",
			stack_line.source_file_name != "" ? stack_line.source_file_name.c_str() : "NoFile"
		);

		string_trace += string_line;
	}

	for (EHRegister& reg : report.register_list)
	{
		if (reg.reg_size == 4)
		{
			string_register_list += SStr_format("4-byte register %s: 0x%08X\n", reg.reg_name.c_str(), reg.reg_value);
		}
		if (reg.reg_size == 8)
		{
			string_register_list += SStr_format("8-byte register %s: 0x%016llX\n", reg.reg_name.c_str(), reg.reg_value);
		}
	}
	string_register_list += "\n";

	std::string string_address = SStr_format((INTPTR_MAX == INT64_MAX) ? "%016llX" : "%08X", report.eh_fault_address);
	std::string string_symbol = report.eh_cpp_exception_symbol != "" ? SStr_format("ExceptionSymbol: %s\n", report.eh_cpp_exception_symbol.c_str()) : "";
	std::string string_message = report.eh_cpp_exception_message != "" ? SStr_format("ExceptionMessage: %s\n", report.eh_cpp_exception_message.c_str()) : "";
	std::string report_header = SStr_format(
		"ExceptionCode: %08X\n"
		"ExceptionAddress: %s\n"
		"%s" // exception symbol
		"%s" // exception message
		"%s" // register list
		"%s" // stack trace
		, report.eh_exception_code
		, string_address.c_str()
		, string_symbol.c_str()
		, string_message.c_str()
		, string_register_list.c_str()
		, string_trace.c_str()
	);

	char* report_buf = (char*)malloc(report_header.size() + 1);
	if (report_buf != NULL)
	{
		memset(report_buf, 0, report_header.size() + 1);
		memcpy(report_buf, report_header.c_str(), report_header.size());
		return { report_buf, report_header.size(), false, true };
	}
	else
	{
		return { (char*)"OOM", 3, false, false };
	};
}

void ExceptionManager::DefaultHandler(ExceptionManager::EHFinishedReport report)
{
	printf("%.*s\n", report.report_size, report.report_string);

	if (report.should_free == true)
	{
		free(report.report_string);
	}

	Sleep(UINT_MAX);
	return;
}

ExceptionManager::EHCompiledReport ExceptionManager::GenerateReport(PEXCEPTION_POINTERS pExceptionRecord)
{
	STACKFRAME stackFrame;
	memset(&stackFrame, 0, sizeof(STACKFRAME));

	EHCompiledReport eh_report;

#if (INTPTR_MAX == INT32_MAX)
	stackFrame.AddrPC.Offset = pExceptionRecord->ContextRecord->Eip;
	stackFrame.AddrStack.Offset = pExceptionRecord->ContextRecord->Esp;
	stackFrame.AddrFrame.Offset = pExceptionRecord->ContextRecord->Ebp;

	DWORD Eax = pExceptionRecord->ContextRecord->Eax,
		Ebx = pExceptionRecord->ContextRecord->Ebx,
		Ecx = pExceptionRecord->ContextRecord->Ecx,
		Edx = pExceptionRecord->ContextRecord->Edx,
		Esi = pExceptionRecord->ContextRecord->Esi,
		Edi = pExceptionRecord->ContextRecord->Edi,
		Eip = pExceptionRecord->ContextRecord->Eip,
		Esp = pExceptionRecord->ContextRecord->Esp,
		Ebp = pExceptionRecord->ContextRecord->Ebp;

	eh_report.register_list = {
		EH_STRREG(Eax),
		EH_STRREG(Ebx),
		EH_STRREG(Ecx),
		EH_STRREG(Edx),
		EH_STRREG(Edi),
		EH_STRREG(Esi),
		EH_STRREG(Eip),
		EH_STRREG(Esp),
		EH_STRREG(Ebp)
	};
#elif (INTPTR_MAX == INT64_MAX)
#if defined (_M_ARM64)
	stackFrame.AddrPC.Offset = pExceptionRecord->ContextRecord->Pc;
	stackFrame.AddrStack.Offset = pExceptionRecord->ContextRecord->Sp;
	stackFrame.AddrFrame.Offset = pExceptionRecord->ContextRecord->Fp;

	for (unsigned r = 0; r < 31; ++r) // yes, 31
		eh_report.register_list.push_back({ Arm64IndexToNameMap[r], (DWORD64)pExceptionRecord->ContextRecord->X[r], 64 / 8 });
	eh_report.register_list.push_back({ "Sp", (DWORD64)pExceptionRecord->ContextRecord->Fp, 64 / 8 });
	eh_report.register_list.push_back({ "Pc", (DWORD64)pExceptionRecord->ContextRecord->Pc, 64 / 8 });
	eh_report.register_list.push_back({ "Fpcr", (DWORD64)pExceptionRecord->ContextRecord->Fpcr, 32 / 8 });
	eh_report.register_list.push_back({ "Fpsr", (DWORD64)pExceptionRecord->ContextRecord->Fpsr, 32 / 8 });
	for (unsigned r = 0; r < ARM64_MAX_BREAKPOINTS; ++r)
	{
		eh_report.register_list.push_back({
			SStr_format("Bcr%i", r),
			(DWORD32)pExceptionRecord->ContextRecord->Bcr[r],
			32 / 8
		});
		eh_report.register_list.push_back({
			SStr_format("Bvr%i", r),
			(DWORD64)pExceptionRecord->ContextRecord->Bvr[r],
			64 / 8
		});
	}
	for (unsigned r = 0; r < ARM64_MAX_WATCHPOINTS; ++r)
	{
		eh_report.register_list.push_back({
			SStr_format("Wcr%i", r),
			(DWORD32)pExceptionRecord->ContextRecord->Wcr[r],
			32 / 8
		});
		eh_report.register_list.push_back({
			SStr_format("Wvr%i", r),
			(DWORD64)pExceptionRecord->ContextRecord->Wvr[r],
			64 / 8
		});
	}
#elif defined (_M_X64)
	stackFrame.AddrPC.Offset = pExceptionRecord->ContextRecord->Rip;
	stackFrame.AddrStack.Offset = pExceptionRecord->ContextRecord->Rsp;
	stackFrame.AddrFrame.Offset = pExceptionRecord->ContextRecord->Rbp;

	DWORD64 Rax = pExceptionRecord->ContextRecord->Rax,
		Rbx = pExceptionRecord->ContextRecord->Rbx,
		Rcx = pExceptionRecord->ContextRecord->Rcx,
		Rdx = pExceptionRecord->ContextRecord->Rdx,
		Rsi = pExceptionRecord->ContextRecord->Rsi,
		Rdi = pExceptionRecord->ContextRecord->Rdi,
		Rip = pExceptionRecord->ContextRecord->Rip,
		Rsp = pExceptionRecord->ContextRecord->Rsp,
		Rbp = pExceptionRecord->ContextRecord->Rbp;

	eh_report.register_list = {
		EH_STRREG(Rax),
		EH_STRREG(Rbx),
		EH_STRREG(Rcx),
		EH_STRREG(Rdx),
		EH_STRREG(Rdi),
		EH_STRREG(Rsi),
		EH_STRREG(Rip),
		EH_STRREG(Rsp),
		EH_STRREG(Rbp)
	};
#endif
#endif

	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Mode = AddrModeFlat;

	SymInitialize(GetCurrentProcess(), NULL, TRUE);

	/* 0: file info
	   1: module info
	   2: line number or ""
	   3: dyn or static addr
	   4: base addr or 0      */

	std::vector<EHStackWalkLine> eh_callstack;

#if (INTPTR_MAX == INT32_MAX)
	while (StackWalk(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), GetCurrentThread(), &stackFrame, pExceptionRecord->ContextRecord, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL))
#elif (INTPTR_MAX == INT64_MAX)
#if defined (_M_X64)
	while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), GetCurrentThread(), &stackFrame, pExceptionRecord->ContextRecord, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL))
#elif defined (_M_ARM64)
	while (StackWalk64(IMAGE_FILE_MACHINE_ARM64, GetCurrentProcess(), GetCurrentThread(), &stackFrame, pExceptionRecord->ContextRecord, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL))
#endif
#endif
	{
		EHStackWalkLine this_call;

		CHAR module_name[MAX_PATH];
		//PCHAR symbolName;
		PCHAR file_name;
		DWORD line_number;

		HMODULE module_mem_base = (HMODULE)SymGetModuleBase(GetCurrentProcess(), stackFrame.AddrPC.Offset);
		if (module_mem_base)
		{
			GetModuleFileNameA(module_mem_base, module_name, MAX_PATH);
			this_call.module_base_address = (uintptr_t)module_mem_base;
			this_call.module_name = module_name;
		}

		DWORD32 offset;
		IMAGEHLP_LINE line;
		line.SizeOfStruct = sizeof line;

		if (SymGetLineFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, (PDWORD)&offset, &line))
		{
			file_name = line.FileName;
			line_number = line.LineNumber;

			this_call.source_file_name = file_name;
			this_call.line = line_number;
		}

		CHAR symbolBuf[sizeof(IMAGEHLP_SYMBOL) + 0xFF];
		PIMAGEHLP_SYMBOL symbol = (PIMAGEHLP_SYMBOL)symbolBuf;
		symbol->SizeOfStruct = sizeof symbolBuf;
		symbol->MaxNameLength = 0xFE;

#if (INTPTR_MAX == INT32_MAX)
		DWORD32 disp;
		if (SymGetSymFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, (PDWORD)&disp, symbol))
#elif (INTPTR_MAX == INT64_MAX)
		DWORD64 disp;
		if (SymGetSymFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, (PDWORD64)&disp, symbol))
#endif
		{
			this_call.function_symbol = symbol->Name;
		}

		uintptr_t file_address = stackFrame.AddrPC.Offset - (uintptr_t)module_mem_base;

		this_call.address = file_address;

		eh_callstack.push_back(this_call);
	}

	eh_report.complete_callstack = eh_callstack;
	eh_report.eh_fault_address = (uintptr_t)pExceptionRecord->ExceptionRecord->ExceptionAddress;
	eh_report.eh_exception_code = (uint32_t)pExceptionRecord->ExceptionRecord->ExceptionCode;

	if (eh_report.eh_exception_code == 0xE06D7363)
	{
		PCHAR temp_symbol = NULL;
		PCHAR temp_message = NULL;
		CHAR exception_symbol[512];

		temp_symbol = GetExceptionSymbol(pExceptionRecord);
		if (temp_symbol != NULL)
		{
#if (INTPTR_MAX == INT32_MAX)
			UnDecorateSymbolName(temp_symbol + 1, exception_symbol, sizeof exception_symbol, UNDNAME_NO_ARGUMENTS | UNDNAME_32_BIT_DECODE);
#elif (INTPTR_MAX == INT64_MAX)
			UnDecorateSymbolName(temp_symbol + 1, exception_symbol, sizeof exception_symbol, UNDNAME_NO_ARGUMENTS);
#endif
			temp_symbol = exception_symbol;

			if (std::find(std::begin(g_ehsettings.blacklist_sym), std::end(g_ehsettings.blacklist_sym), (std::string)temp_symbol) != std::end(g_ehsettings.blacklist_sym))
			{
				eh_report.should_ignore = true;
			}

			eh_report.eh_cpp_exception_symbol = (std::string)temp_symbol;
		}

		temp_message = GetExceptionMessage(pExceptionRecord);
		if (temp_message != NULL)
		{
			eh_report.eh_cpp_exception_message = (std::string)temp_message;
		}
	}

	SymCleanup(GetCurrentProcess());

	if (IsXStatePresent()) /* present on Windows 7 SP1+ */
	{
#if defined(_M_X64) || defined (_M_IX86)
		PM128A xmm_array = NULL, ymm_array = NULL, zmm_array = NULL;
		DWORD xmm_len, ymm_len, zmm_len;

		DWORD64 feature_mask = _GetEnabledXStateFeatures();
		if (feature_mask & XSTATE_LEGACY_SSE)
			xmm_array = (PM128A)_LocateXStateFeature(pExceptionRecord->ContextRecord, XSTATE_LEGACY_SSE, &xmm_len);
		if (feature_mask & XSTATE_MASK_AVX)
			ymm_array = (PM128A)_LocateXStateFeature(pExceptionRecord->ContextRecord, XSTATE_AVX, &ymm_len);
		if (feature_mask & XSTATE_MASK_AVX512)
			zmm_array = (PM128A)_LocateXStateFeature(pExceptionRecord->ContextRecord, XSTATE_AVX512_ZMM, &zmm_len);

		if (xmm_array != NULL)
		{
			for (unsigned r = 0; r < xmm_len / sizeof(*xmm_array); r += 1)
			{
				eh_report.register_list.push_back({ SStr_format("xmm%i_%i", r, 0), (DWORD64)xmm_array[r].Low,  64 / 8 });
				eh_report.register_list.push_back({ SStr_format("xmm%i_%i", r, 1), (DWORD64)xmm_array[r].High, 64 / 8 });
			}
		}
		if (ymm_array != NULL)
		{
			for (unsigned r = 0; r < ymm_len / sizeof(*ymm_array); r += 1)
			{
				eh_report.register_list.push_back({ SStr_format("ymm%i_%i", r, 0), (DWORD64)ymm_array[r].Low,  64 / 8 });
				eh_report.register_list.push_back({ SStr_format("ymm%i_%i", r, 1), (DWORD64)ymm_array[r].High, 64 / 8 });
			}
		}
		if (zmm_array != NULL) // needs to be tested
		{
			for (unsigned r = 0; r < zmm_len / sizeof(*zmm_array); r += 2)
			{
				M128A zmmx_lo = zmm_array[r + 0];
				M128A zmmx_hi = zmm_array[r + 1];
				eh_report.register_list.push_back(EHRegister( SStr_format("zmm%i_%i", r, 0), (DWORD64)zmmx_lo.Low,  64 / 8 ));
				eh_report.register_list.push_back(EHRegister( SStr_format("zmm%i_%i", r, 1), (DWORD64)zmmx_lo.High, 64 / 8 ));
				eh_report.register_list.push_back(EHRegister( SStr_format("zmm%i_%i", r, 2), (DWORD64)zmmx_hi.Low,  64 / 8 ));
				eh_report.register_list.push_back(EHRegister( SStr_format("zmm%i_%i", r, 3), (DWORD64)zmmx_hi.High, 64 / 8 ));
			}
		}
	}
#endif
#if defined(_M_ARM64)
	// armv8-a spec has NEON and VFP as mandatory features; no need to check if it is available
	for (unsigned r = 0; r < 32; ++r)
	{
		eh_report.register_list.push_back({ SStr_format("d%i_lo", r), (DWORD64)pExceptionRecord->ContextRecord->V[r].D[0], 64 / 8 });
		eh_report.register_list.push_back({ SStr_format("d%i_hi", r), (DWORD64)pExceptionRecord->ContextRecord->V[r].D[1], 64 / 8 });
	}
#endif
	return eh_report;
}

std::string ExceptionManager::ResolveModuleFromAddress(DWORD Address)
{
	std::string result("UnkMod");

	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	DWORD processID = GetCurrentProcessId();

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (unsigned m = 0; m < (cbNeeded / sizeof(HMODULE)); m++)
		{
			MODULEINFO modInfo;
			GetModuleInformation(hProcess, hMods[m], &modInfo, sizeof(MODULEINFO));
			uintptr_t BaseAddress = (uintptr_t)modInfo.lpBaseOfDll;
			if (Address > BaseAddress && Address < (BaseAddress + modInfo.SizeOfImage))
			{
				char ModuleName[MAX_PATH];
				GetModuleFileNameExA(hProcess, hMods[m], ModuleName, MAX_PATH);

				result = getBack(ModuleName, '\\');
				break;
			}
		}
	}

	CloseHandle(hProcess);

	return result;
}

PCHAR ExceptionManager::GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionRecord)
{
#if (INTPTR_MAX == INT32_MAX)
	PDWORD L0 = (PDWORD)pExceptionRecord->ExceptionRecord->ExceptionInformation[2];
	if (L0 != NULL)
	{
		PDWORD L1 = (PDWORD)L0[3];
		if (L1 != NULL)
		{
			PDWORD L2 = (PDWORD)L1[1];
			if (L2 != NULL)
			{
				PCHAR Symbol = (PCHAR)(L2[1] + 8);
				return Symbol;
			}
		}
	}
	return NULL;
#elif (INTPTR_MAX == INT64_MAX)
	DWORD numparams = pExceptionRecord->ExceptionRecord->NumberParameters;
	if (numparams >= 4)
	{
		ULONG_PTR syminfo = pExceptionRecord->ExceptionRecord->ExceptionInformation[2];
		if (syminfo != NULL)
		{
			ULONG_PTR base = pExceptionRecord->ExceptionRecord->ExceptionInformation[3];
			DWORD offset = *(DWORD*)(syminfo + 0x0C);
			if (offset != NULL)
			{
				ULONG_PTR sym_struct1 = base + offset;
				if (sym_struct1 != NULL)
				{
					ULONG_PTR sym_struct2 = base + *(DWORD*)(sym_struct1 + 0x04);
					if (sym_struct2 != NULL)
					{
						ULONG_PTR sym_struct3 = base + *(DWORD*)(sym_struct2 + 0x04);
						return (PCHAR)(sym_struct3 + 0x10);
					}
				}
			}
		}
	}
	return NULL;
#endif
}

PCHAR ExceptionManager::GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord)
{
#if (INTPTR_MAX == INT32_MAX)
	PCHAR Message = NULL;

	PDWORD L0 = (PDWORD)pExceptionRecord->ExceptionRecord->ExceptionInformation[1];
	if (L0 != NULL)
	{
		Message = (PCHAR)L0[1];
		if (Message == NULL)
		{
			Message = (PCHAR)L0[3];
		}
	}
	return Message;
#elif (INTPTR_MAX == INT64_MAX)
	ULONG_PTR ExceptionInfo_Unk1 = pExceptionRecord->ExceptionRecord->ExceptionInformation[1];
	return *(PCHAR*)(ExceptionInfo_Unk1 + 0x08);
#endif
}

BOOL ExceptionManager::ProcessException(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord)
{
	EHCompiledReport compiled_report = GenerateReport(pExceptionRecord);
	if (compiled_report.should_ignore == true)
	{
		return TRUE;
	}

	EHFinishedReport processed_report = g_ehsettings.proc_callback(compiled_report);
	g_ehsettings.recv_callback(processed_report);

	return FALSE;
}

struct ThreadParams
{
	bool isVEH;
	PEXCEPTION_POINTERS pEH;
	DWORD* ret;
};

void EH_ThreadFunction(void* arg)
{
	ThreadParams* args = (ThreadParams*)arg;
	PEXCEPTION_POINTERS pExceptionRecord = args->pEH;
	if (std::find(std::begin(ExceptionManager::g_ehsettings.blacklist_code), std::end(ExceptionManager::g_ehsettings.blacklist_code), pExceptionRecord->ExceptionRecord->ExceptionCode) != std::end(ExceptionManager::g_ehsettings.blacklist_code))
	{
		*args->ret = EXCEPTION_CONTINUE_SEARCH;
		return;
	}

	if (ExceptionManager::ProcessException(args->isVEH, pExceptionRecord) == TRUE)
	{
		*args->ret = EXCEPTION_CONTINUE_SEARCH; // Upon further analysis, this is a non-fatal exception and should be skipped
		return;
	}

	*args->ret = EXCEPTION_NONCONTINUABLE_EXCEPTION;
	return;
}

LONG WINAPI ExceptionManager::TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord)
{
	DWORD ret = EXCEPTION_NONCONTINUABLE_EXCEPTION;
	ThreadParams params;
	params.ret = &ret;
	params.isVEH = false;
	params.pEH = pExceptionRecord;

	HANDLE eh_thread = CreateThread(NULL, 0x10000, (LPTHREAD_START_ROUTINE)EH_ThreadFunction, (void*)&params, NULL, NULL);
	if (eh_thread != NULL)
	{
		WaitForSingleObject(eh_thread, INFINITE);
	}
	else
	{
		// well shit
		__fastfail(GetLastError());
	}

	if (ret == EXCEPTION_NONCONTINUABLE_EXCEPTION)
	{
		exit(pExceptionRecord->ExceptionRecord->ExceptionCode);
	}

	return ret;
}

LONG WINAPI ExceptionManager::VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord)
{
	DWORD ret;
	ThreadParams params;
	params.ret = &ret;
	params.isVEH = true;
	params.pEH = pExceptionRecord;

	HANDLE eh_thread = CreateThread(NULL, 0x10000, (LPTHREAD_START_ROUTINE)EH_ThreadFunction, (void*)&params, NULL, NULL);
	WaitForSingleObject(eh_thread, INFINITE);

	if (ret == EXCEPTION_NONCONTINUABLE_EXCEPTION)
	{
		exit(pExceptionRecord->ExceptionRecord->ExceptionCode);
	}

	return ret;
	/*if (pExceptionRecord->ExceptionRecord->ExceptionCode == STATUS_STACK_OVERFLOW)
	{
		HANDLE Event = RegisterEventSourceA(NULL, EH_EVENTNAME);
		PCHAR EventString = (PCHAR)malloc(0x100);

		if (EventString != NULL)
		{
			//sprintf_s(EventString, 0x100, "")
			if (Event != NULL)
			{
				ReportEventA(Event, EVENTLOG_ERROR_TYPE, 0, 0, NULL, 1, 0, &EventString, NULL);
				free(EventString);
				CloseHandle(Event);
			}
			// Event == NULL
			free(EventString);
		}
	}*/
}

void ExceptionManager::Init(EHSettings* settings)
{
	HMODULE kernel32_handle = GetModuleHandleA("kernel32.dll");
	if (kernel32_handle != NULL)
	{
		_GetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)GetProcAddress(kernel32_handle, "GetEnabledXStateFeatures");
		_LocateXStateFeature = (LOCATEXSTATEFEATURE)GetProcAddress(kernel32_handle, "LocateXStateFeature");
	}
	g_ehsettings = *settings;
	if (g_ehsettings.report_dst == NULL) g_ehsettings.report_dst = g_ehreportbuffer;
	if (g_ehsettings.report_dst_size == NULL) g_ehsettings.report_dst_size = EH_REPORTSIZE;
	if (g_ehsettings.prog_base != NULL && g_ehsettings.prog_size == NULL)
	{
		/* todo: look into whether MODULEINFO::lpBaseOfDll actually means it has to be a DLL base? */
		MODULEINFO mi;
		GetModuleInformation(GetCurrentProcess(), (HMODULE)g_ehsettings.prog_base, &mi, sizeof(MODULEINFO));
		g_ehsettings.prog_size = mi.SizeOfImage;
	}
	if (g_ehsettings.use_seh == true)
	{
		typedef VOID(WINAPI* TopLevelException)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
		HMODULE ntdll_handle = GetModuleHandleA("ntdll.dll");
		if (ntdll_handle != NULL)
		{
			TopLevelException RtlSetUnhandledExceptionFilter = (TopLevelException)GetProcAddress(ntdll_handle, "RtlSetUnhandledExceptionFilter");
			RtlSetUnhandledExceptionFilter(TopLevelExceptionHandler);
		}
	}
	if (g_ehsettings.use_veh == true)
	{
		typedef VOID(WINAPI* VectoredException)(ULONG First, PVECTORED_EXCEPTION_HANDLER lpVectorExceptionFilter);
		HMODULE ntdll_handle = GetModuleHandleA("ntdll.dll");
		if (ntdll_handle != NULL)
		{
			VectoredException RtlAddVectoredExceptionHandler = (VectoredException)GetProcAddress(ntdll_handle, "RtlAddVectoredExceptionHandler");
			RtlAddVectoredExceptionHandler(0, VectoredExceptionHandler);
		}
	}

	return;
}