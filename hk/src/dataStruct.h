#pragma once

#include "define.h"

struct DTGlobal {
  DWORD PID = 0;

  HANDLE hProcess = NULL;
  HANDLE hTInject = NULL;
  DWORD TID = 0;
  void* pAllocatedAddress = NULL;

  HMODULE hLocalDLL = nullptr;

  std::wstring dllName = TEXT("hklib.dll");
  uint64_t dllBaseAddr = 0;
  std::map<std::string, DWORD> remoteFunctions;
  std::wstring dllRelativePath = TEXT("hklib.dll");
  std::wstring dllFullPath = std::wstring();

  BOOL addFunction(LPCSTR function) noexcept;					// must call updateOffsets() when done adding functions
  BOOL removeFunction(LPCSTR function) noexcept;
  BOOL storeOffset(LPCSTR function, DWORD offset) noexcept;
  void updateOffsets() noexcept;								// call after every new remote function added
  DWORD offsetOf(LPCSTR function) noexcept;
};

struct FunctionData {
  std::string sName = "";
  DWORD dwOffset = 0;
  DWORD dwDataSize = 0;
};

struct DTImport {
  std::vector<std::string> modules;
  std::map<std::string, std::vector<FunctionData>> functionsEx;

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

extern DTGlobal global;
extern DTImport dataImport;