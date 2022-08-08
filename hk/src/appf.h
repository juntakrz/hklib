#pragma once

#include "define.h"
#include "hkutil.h"
#include "hklocal.h"
#include "hkdll.h"

// appf_core
void		printHelp() noexcept;							// output help messages to console
int			parseArgs(int argc, wchar_t* argv[]);			// parse commandline arguments

void        analyzeTarget() noexcept;
void        testShellCode() noexcept;                       // just a basic shellcode testing function

void        presentResults() noexcept;

// appf_get
DWORD		getProcessID(const wchar_t* process) noexcept;	// resolve PID from process name