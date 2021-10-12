#include "./ExceptionHandler.hpp"

HMODULE programDll = 0;

std::string ExceptionManager::getBack(const std::string& s, char delim) {
	std::stringstream ss(s);
	std::string item;

	while (std::getline(ss, item, delim));

	return item;
}

std::string ExceptionManager::StackWalkReport(PEXCEPTION_POINTERS pExceptionRecord)
{
	std::stringstream StackWalkReport;

	STACKFRAME stackFrame;
	memset(&stackFrame, 0, sizeof(STACKFRAME));

	stackFrame.AddrPC.Offset = pExceptionRecord->ContextRecord->Eip;
	stackFrame.AddrStack.Offset = pExceptionRecord->ContextRecord->Esp;
	stackFrame.AddrFrame.Offset = pExceptionRecord->ContextRecord->Ebp;

	DWORD Eax = pExceptionRecord->ContextRecord->Eax,
		Ebx = pExceptionRecord->ContextRecord->Ebx,
		Ecx = pExceptionRecord->ContextRecord->Ecx,
		Edx = pExceptionRecord->ContextRecord->Edx,
		Esi = pExceptionRecord->ContextRecord->Esi,
		Edi = pExceptionRecord->ContextRecord->Edi;

	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrStack.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Mode = AddrModeFlat;

	SymInitialize(GetCurrentProcess(), NULL, TRUE);


	std::vector<std::vector<std::string>> reportStringParseCache{};

	size_t fileInfoStrMax = 0, fileInfoStrTemp = 0;
	size_t moduleInfoStrMax = 0, moduleInfoStrTemp = 0;
	size_t lineNumberStrMax = 0, lineNumberStrTemp = 0;
	size_t dynAddrStrMax = 0, dynAddrStrTemp = 0;
	size_t constAddrStrMax = 0, constAddrStrTemp = 0;
	size_t baseAddrStrMax = 0, baseAddrStrTemp = 0;
	/* 0: file info
	   1: module info
	   2: line number or ""
	   3: dyn or static addr
	   4: base addr or 0      */

	while (StackWalk(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), GetCurrentThread(), &stackFrame, pExceptionRecord->ContextRecord, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL))
	{
		CHAR moduleName[MAX_PATH];
		PCHAR symbolName;
		PCHAR fileName;
		DWORD lineNumber;

		HMODULE moduleBase = (HMODULE)SymGetModuleBase(GetCurrentProcess(), stackFrame.AddrPC.Offset);
		if (moduleBase)
		{
			GetModuleFileNameA(moduleBase, moduleName, MAX_PATH);
		}
		else
		{
			sprintf_s(moduleName, "UnkMod");
		}

		CHAR symbolBuf[sizeof(IMAGEHLP_SYMBOL) + 255];
		PIMAGEHLP_SYMBOL symbol = (PIMAGEHLP_SYMBOL)symbolBuf;
		symbol->SizeOfStruct = sizeof symbolBuf;
		symbol->MaxNameLength = 254;

		DWORD offset;
		symbolName = SymGetSymFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, &offset, symbol)
			? symbol->Name : PCHAR("UnkSym");

		IMAGEHLP_LINE line;
		line.SizeOfStruct = sizeof line;

		if (SymGetLineFromAddr(GetCurrentProcess(), stackFrame.AddrPC.Offset, &offset, &line))
		{
			fileName = line.FileName;
			lineNumber = line.LineNumber;
		}
		else
		{
			fileName = PCHAR("UnkFile");
			lineNumber = 0;
		}

		if (moduleBase == 0)
		{
			MODULEINFO swModuleInfo;
			GetModuleInformation(GetCurrentProcess(), programDll, &swModuleInfo, sizeof(MODULEINFO));
			if (stackFrame.AddrPC.Offset > (DWORD)programDll && stackFrame.AddrPC.Offset < (DWORD)programDll + swModuleInfo.SizeOfImage)
			{
				if (!GetModuleFileNameA(programDll, moduleName, sizeof moduleName))
				{
					sprintf_s(moduleName, "YourModuleNameHere.dll");
					moduleBase = programDll;
				}
			}
		}
		DWORD normalizedAddress = stackFrame.AddrPC.Offset - (DWORD)moduleBase + 0x400000;

		CHAR tempFileInfoString[96];
		CHAR tempModuleInfoString[MAX_PATH];
		CHAR tempLineInfoString[24];
		CHAR tempDynAddrString[32];
		CHAR tempConstAddrString[32];
		CHAR tempBaseAddrString[32];

		sprintf_s(tempFileInfoString, "[File: %s]", getBack(fileName, '\\').c_str());
		sprintf_s(tempModuleInfoString, sizeof tempModuleInfoString, moduleBase != 0 ? "[Module: %s]" : "", getBack(moduleName, '\\').c_str());
		sprintf_s(tempLineInfoString, lineNumber != 0 ? "[Line: %i]" : "", lineNumber);
		sprintf_s(tempDynAddrString, "[DynamicAddr: 0x%08X]", normalizedAddress);
		sprintf_s(tempConstAddrString, "[RebaseAddr: 0x%08X]", normalizedAddress);
		sprintf_s(tempBaseAddrString, "[BaseAddr: 0x%08X]", (DWORD)moduleBase);

		fileInfoStrMax = fileInfoStrMax < (fileInfoStrTemp = strlen(tempFileInfoString)) ? fileInfoStrTemp : fileInfoStrMax;
		moduleInfoStrMax = moduleInfoStrMax < (moduleInfoStrTemp = strlen(tempModuleInfoString)) ? moduleInfoStrTemp : moduleInfoStrMax;
		lineNumberStrMax = lineNumberStrMax < (lineNumberStrTemp = strlen(tempLineInfoString)) ? lineNumberStrTemp : lineNumberStrMax;
		dynAddrStrMax = dynAddrStrMax < (dynAddrStrTemp = strlen(tempDynAddrString)) ? dynAddrStrTemp : dynAddrStrMax;
		constAddrStrMax = constAddrStrMax < (constAddrStrTemp = strlen(tempConstAddrString)) ? constAddrStrTemp : constAddrStrMax;
		baseAddrStrMax = baseAddrStrMax < (baseAddrStrTemp = strlen(tempBaseAddrString)) ? baseAddrStrTemp : baseAddrStrMax;

		std::vector<std::string> stringParseVector{
			tempFileInfoString,
			tempModuleInfoString,
			lineNumber != 0 ? tempLineInfoString : "",
			moduleBase == 0 ? tempDynAddrString : tempConstAddrString,
			moduleBase != 0 ? tempBaseAddrString : "" // if empty, omit
		};

		reportStringParseCache.push_back(stringParseVector);
	}

	SymCleanup(GetCurrentProcess());

	CHAR stackWalkReportLine[384];

	for (std::vector<std::string>& stackFrameReportLine : reportStringParseCache)
	{
		memset(stackWalkReportLine, 0, sizeof stackWalkReportLine);
		/* 0: file info
		   1: module info
		   2: line number or ""
		   3: dyn or static addr
		   4: base addr or 0      */

		const std::string& fileInfo = stackFrameReportLine[0];
		const std::string& moduleInfo = stackFrameReportLine[1];
		const std::string& lineNumber = stackFrameReportLine[2];
		const std::string& addrInfo = stackFrameReportLine[3];
		const std::string& baseAddrInfo = stackFrameReportLine[4];

		std::string fmtFileInfo(fileInfoStrMax, ' ');
		std::string fmtModuleInfo(moduleInfoStrMax, ' ');
		std::string fmtLineNumber(lineNumberStrMax, ' ');
		std::string fmtAddrInfo(dynAddrStrMax > constAddrStrMax ? dynAddrStrMax : constAddrStrMax, ' ');
		std::string fmtBaseAddrInfo(baseAddrStrMax, ' ');

		memcpy((void*)fmtFileInfo.c_str(), fileInfo.c_str(), fileInfo.size());
		memcpy((void*)fmtModuleInfo.c_str(), moduleInfo.c_str(), moduleInfo.size());
		memcpy((void*)fmtLineNumber.c_str(), lineNumber.c_str(), lineNumber.size());
		memcpy((void*)fmtAddrInfo.c_str(), addrInfo.c_str(), addrInfo.size());
		memcpy((void*)fmtBaseAddrInfo.c_str(), baseAddrInfo.c_str(), baseAddrInfo.size());

		sprintf_s(
			stackWalkReportLine,
			"%s %s %s %s %s"
			, fmtFileInfo.c_str()
			, fmtModuleInfo.c_str()
			, fmtLineNumber.c_str()
			, fmtAddrInfo.c_str()
			, fmtBaseAddrInfo.c_str()
		);

		StackWalkReport << stackWalkReportLine << "\n";
	}

	return StackWalkReport.str();
}

std::string ExceptionManager::ResolveModuleFromAddress(DWORD Address)
{
	std::string result("UnkMod");

	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	auto processID = GetCurrentProcessId();

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (unsigned m = 0; m < (cbNeeded / sizeof(HMODULE)); m++)
		{
			MODULEINFO modInfo;
			GetModuleInformation(hProcess, hMods[m], &modInfo, sizeof(MODULEINFO));
			auto BaseAddress = DWORD(modInfo.lpBaseOfDll);
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
	// credit to raymond chen, now only if i could get the message within the exception and not just the symbol.
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
}

PCHAR ExceptionManager::GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord)
{
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
}

BOOL ExceptionManager::ExceptionNotify(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord)
{
	auto ExceptionAddress = pExceptionRecord->ExceptionRecord->ExceptionAddress;
	auto ExceptionCode = pExceptionRecord->ExceptionRecord->ExceptionCode;

	char UserMessage[8192];

	PCHAR Symbol = NULL;
	PCHAR Message = NULL;
	CHAR DecodedSymbol[512];

	if (ExceptionCode == 0xe06d7363) /* C++ exception not caught in top level */
	{
		Symbol = GetExceptionSymbol(pExceptionRecord);
		if (Symbol != NULL)
		{
			UnDecorateSymbolName(Symbol + 1, DecodedSymbol, sizeof DecodedSymbol, UNDNAME_NO_ARGUMENTS | UNDNAME_32_BIT_DECODE);
			Symbol = DecodedSymbol;
		}
		Message = GetExceptionMessage(pExceptionRecord);
	}
	sprintf_s(
		UserMessage,

		"[Code = 0x%08X]"      "\n"
		"[ExceptSymbol = %s]"  "\n"
		"[Message = %s]"       "\n"
		"[Eip = 0x%08X]"       "\n"
		"[Eax = 0x%08X]"       "\n"
		"[Ebx = 0x%08X]"       "\n"
		"[Ecx = 0x%08X]"       "\n"
		"[Edx = 0x%08X]"       "\n"
		"[Esi = 0x%08X]"       "\n"
		"[Edi = 0x%08X]"       "\n"
		"[Ebp = 0x%08X]"       "\n"
		"[Esp = 0x%08X]"       "\n"

		"[Dll Base = 0x%08x]"  "\n"
		"\n"
		"%s"
		, ExceptionCode
		, Symbol ? Symbol : "NoSym"
		, Message ? Message : "NoMsg"
		, pExceptionRecord->ContextRecord->Eip
		, pExceptionRecord->ContextRecord->Eax
		, pExceptionRecord->ContextRecord->Ebx
		, pExceptionRecord->ContextRecord->Ecx
		, pExceptionRecord->ContextRecord->Edx
		, pExceptionRecord->ContextRecord->Esi
		, pExceptionRecord->ContextRecord->Edi
		, pExceptionRecord->ContextRecord->Ebp
		, pExceptionRecord->ContextRecord->Esp
		, (DWORD)programDll
		, StackWalkReport(pExceptionRecord).c_str()
	);

	std::string messageString;

	messageString = UserMessage;

	auto autogeneratedCrashReportName = [&]()
	{
		time_t t = time(0);   // get time now
		struct tm* now = localtime(&t);

		char buffer[80];
		strftime(buffer, 80, "%d-%m-%Y_%H-%M-%S_ProgramCrash.txt", now);
		return std::string(buffer);
	};

	auto fileName = autogeneratedCrashReportName();


	if (!std::filesystem::exists(fileName))
	{
		std::ofstream F(fileName.c_str(), std::ios::binary);
		if (F.is_open())
		{
			F.write(messageString.c_str(), messageString.size());
			F.close();
		}
		//else
		//{
		//	Log("Failed to create file: %08x\n", GetLastError());
		//}
	}
	//else
	//{
	//	Log("Something failed very badly\n");
	//}

	/* Check to see if a file already exists, because some users reported that the crash report disappeared when they went to get it later. */
	/* the first crash report written at that very second is probably the relevant one. */

	STARTUPINFOA stinfo;
	PROCESS_INFORMATION prinfo;
	CreateProcessA(
		"C:\\Windows\\System32\\notepad.exe",
		(LPSTR)(("notepad.exe ") + fileName).c_str(),
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&stinfo,
		&prinfo
	);

	printf("crash report created\n");

	Sleep(UINT_MAX);

	return FALSE;
}

LONG WINAPI ExceptionManager::TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord)
{
	ExceptionNotify(false, pExceptionRecord);

	exit(1);

	return EXCEPTION_NONCONTINUABLE_EXCEPTION;
}

LONG WINAPI ExceptionManager::VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord)
{
	switch (auto code = pExceptionRecord->ExceptionRecord->ExceptionCode)
	{
	case 0x80000004:
	case 0x80000006:
	case 0x40010006:
	case 0x406d1388: /* Debugger detection...? */
		//Log("Blacklisted exception: 0x%08X\n", code);
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (ExceptionNotify(true, pExceptionRecord) == TRUE)
	{
		return EXCEPTION_CONTINUE_SEARCH; /* Upon further analysis, this is a non-fatal exception and should be skipped */
	}

	exit(1);

	return EXCEPTION_NONCONTINUABLE_EXCEPTION;
}

void ExceptionManager::Init()
{
	typedef VOID(WINAPI* TopLevelException)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
	typedef VOID(WINAPI* VectoredException)(ULONG First, PVECTORED_EXCEPTION_HANDLER lpVectorExceptionFilter);

	TopLevelException RtlSetUnhandledExceptionFilter = (TopLevelException)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlSetUnhandledExceptionFilter");
	VectoredException RtlAddVectoredExceptionHandler = (VectoredException)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddVectoredExceptionHandler");

	RtlSetUnhandledExceptionFilter(TopLevelExceptionHandler);
	RtlAddVectoredExceptionHandler(0, VectoredExceptionHandler);
	/* 
	note: 
	if you are using this exception handler and injecting it into an external application, 
	it would be wise to comment out the VEH (RtlAddVectoredExceptionHandler) registration in order to avoid catching what will be handled exceptions in code outside of your control.
	*/
}