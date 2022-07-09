#pragma once

#ifdef MAKEDLL
#define EXPORT __declspec(dllexport)
#define C_EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#define C_EXPORT extern "C" __declspec(dllimport)
#endif

struct _DATA_IMPORT {
  std::vector<std::string> modules;
  std::map<std::string, std::vector<std::string>> functions;
  DWORD dwDataSize = 0;
};

struct _DATA_LOCAL {
  PBYTE						pBaseAddr = nullptr;
  PIMAGE_DOS_HEADER			pDOSHdr	= nullptr;
  PIMAGE_NT_HEADERS			pNTHdr	= nullptr;
  PIMAGE_OPTIONAL_HEADER	pOptHdr = nullptr;
  HANDLE					hSharedMem = NULL;
};

extern _DATA_IMPORT dataImport;
extern _DATA_LOCAL	dataLocal;