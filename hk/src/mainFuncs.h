#pragma once

#include "CFileProc.h"
#include "CBufferProc.h"

void printHelp() noexcept;
int processArgs(int argc, wchar_t* argv[]);
void presentResults(CBufferProc* execBuffer,
                    bool isDetailed = true) noexcept;
int inject(const DWORD& procID) noexcept;