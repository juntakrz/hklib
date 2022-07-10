#pragma once

#include "pch.h"

#define LOG(x) std::cout << x << "\n"
#define wLOG(x) std::wcout << x << "\n"

#define ERRCHK                  \
  DWORD error = GetLastError();	\
  if (error) { printf("Error code: %d\n\nPress ANY key to exit.\n", error); _getch(); exit(error); }

enum class bufferType { none = 0, exec, icon };
enum class appMode { none = 0, analyze, inject };