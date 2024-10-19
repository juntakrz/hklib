#pragma once

#ifdef MAKEDLL
#define EXPORT __declspec(dllexport)
#define C_EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#define C_EXPORT extern "C" __declspec(dllimport)
#endif

struct DATA_IMPORT {
  std::vector<std::string> modules;
  std::map<std::string, std::vector<std::string>> functions;
  DWORD dwDataSize = 0;
  const char* szShareName = "%HKDATA%";
  const BYTE delimiter = 0x1F;
};

struct DATA_LOCAL {
  PBYTE						pBaseAddress = nullptr;
  PIMAGE_DOS_HEADER			pDOSHeader	= nullptr;
  PIMAGE_NT_HEADERS			pNTHeader	= nullptr;
  PIMAGE_OPTIONAL_HEADER	pOptionalHeader = nullptr;
  HANDLE					hSharedMemory = NULL;
};

extern DATA_IMPORT dataImport;
extern DATA_LOCAL	dataLocal;