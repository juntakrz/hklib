#pragma once

#include "define.h"

struct dtGlobal {
  DWORD PID = 0;

  HANDLE hProc = NULL;
  HANDLE hTInject = NULL;
  DWORD TID = 0;
  void* pAllocatedArg = NULL;

  HMODULE hLocalDLL = nullptr;

  std::wstring dllName = L"hklib.dll";
  uint64_t dllBaseAddr = 0;
  std::map<std::string, DWORD> remoteFunctions;
  std::string dllRelativePath = "hklib.dll";
  std::string dllFullPath = "";

  BOOL addFunction(LPCSTR function) noexcept;					// must call updateOffsets() when done adding functions
  BOOL removeFunction(LPCSTR function) noexcept;
  BOOL storeOffset(LPCSTR function, DWORD offset) noexcept;
  void updateOffsets() noexcept;								// call after every new remote function added
  DWORD offsetOf(LPCSTR function) noexcept;
};

struct SFuncData {
  std::string sName = "";
  DWORD dwOffset = 0;
  DWORD dwDataSize = 0;
};

struct dtImport {
  std::vector<std::string> modules;
  std::map<std::string, std::vector<SFuncData>> functionsEx;

  std::map<std::string, std::vector<std::string>> functions;  // to be replaced with functionsEx data structure

  void clear() noexcept;
};

struct hkShellCode {
  unsigned char* pData = nullptr;
  size_t size = 0;

  hkShellCode(void* ptrToData, size_t sizeOfData) {
    pData = (unsigned char*)ptrToData;
    size = sizeOfData;
  }
};

extern dtGlobal global;
extern dtImport dataImport;