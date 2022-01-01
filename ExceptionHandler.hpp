#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <sstream>

extern HMODULE programDll; // set this if you want the program to attempt to resolve what your module is when debug info is not available

namespace ExceptionManager
{
	std::string getBack(const std::string& s, char delim);
	std::string ResolveModuleFromAddress(DWORD Address);
	PCHAR GetExceptionSymbol(PEXCEPTION_POINTERS pExceptionRecord);
	PCHAR GetExceptionMessage(PEXCEPTION_POINTERS pExceptionRecord);
	std::string StackWalkReport(PEXCEPTION_POINTERS pExceptionRecord);
	BOOL ExceptionNotify(bool isVEH, PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionRecord);
	void Init();
};