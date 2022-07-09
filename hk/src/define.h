#pragma once

#include "pch.h"

#define LOG(x) std::cout << x << "\n"
#define wLOG(x) std::wcout << x << "\n"

#define ERRCHK                  \
  { DWORD error = GetLastError();	\
  if (error) { printf("Error code: %d\n\nPress ANY key to exit.\n", error); _getch(); exit(error); }}

#define NULL_THREAD *((HANDLE*)0)
#define NULL_ID *((DWORD*)0)

enum callFlags {
  CALL_NORMAL		= 0,		// standard call
  CALL_NO_WAIT		= 1 << 0,	// don't wait for thread
  CALL_NO_CLOSE		= 1 << 1,	// don't close handle automatically
  CALL_NO_RETURN	= 1 << 2	// don't return a DWORD result from thread
};