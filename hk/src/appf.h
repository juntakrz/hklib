#pragma once

#include "define.h"
#include "util/util.h"

// appf_core
void		printHelp() noexcept;							// output help messages to console
int			parseArgs(int argc, wchar_t* argv[]);			// parse commandline arguments
void        analyzeTarget() noexcept;

// appf_dll
void        dllInject(DWORD PID = 0) noexcept;              // injects DLL and fills global variables
void        dllEject() noexcept;

/*
 * Calls function of an injected DLL.
 * If CALL_NO_CLOSE flag is set - will not automatically shut down the thread
 * and will return its handle and id. Optional: provide an argument (can be an
 * array of char) and its size to send it to a remote thread
 */
DWORD       dllCall(LPCSTR function, HANDLE& out_hThread, DWORD& out_idThread,
                      DWORD flags = 0, PBYTE pArg = nullptr, DWORD sizeArg = 0) noexcept;

// appf_get
DWORD		getProcessID(const wchar_t* process) noexcept;	// resolve PID from process name
uint64_t	getDLLBaseAddr() noexcept;						// base address of the injected DLL
DWORD		getDLLExportOffset(LPCSTR funcName) noexcept;	// address of declared export function (requires injectDLL() first)

void		presentResults() noexcept;  //OBSOLETE