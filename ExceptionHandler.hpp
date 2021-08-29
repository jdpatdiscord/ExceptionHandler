#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <sstream>

extern HMODULE scriptwareDll;

namespace ExceptionManager
{
	std::string getBack(const std::string& s, char delim);
	std::string ResolveModuleFromAddress(DWORD Address);
	PCHAR GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionRecord);
	std::string StackWalkReport(PEXCEPTION_POINTERS pExceptionRecord);
	BOOL ExceptionNotify(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	void Init();
};