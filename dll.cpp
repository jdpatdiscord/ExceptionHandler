#include "ExceptionHandler.hpp"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        ExceptionManager::EHSettings settings ={
            { 0x80000004,
	    	  0x80000006,
	    	  0x40010006,
	    	  0x406D1388 },
	    	{ },
	    	"EH DLL",
	    	(std::uintptr_t)GetModuleHandle(NULL),
	    	NULL,
	    	ExceptionManager::DefaultHandler,
	    	ExceptionManager::DefaultProcessor,
	    	NULL,
	    	NULL,            
	    	false,
	    	true,
	    	false
	    };
        ExceptionManager::Init(&settings);
        return TRUE;
    }
    return TRUE;
}