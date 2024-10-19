#include "pch.h"
#include "dllfunc.h"

C_EXPORT DWORD exportPEImageData() noexcept {
  const char* szShareName = "%HKDATA%";

  analyzePEImage();

  // Calculate size of resulting data
  dataImport.dwDataSize = 0;

  for (const auto& it_module : dataImport.modules) {
    dataImport.dwDataSize += (DWORD)it_module.size() + 1;

    if (it_module.size()) {
      dataImport.dwDataSize++;  // Add one byte for delimiter
      for (const auto& it_func : dataImport.functions.at(it_module)) {
        dataImport.dwDataSize += (DWORD)it_func.size() + 1;
      }
      dataImport.dwDataSize++;  // Add one byte for delimiter
    }
  }

  dataLocal.hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, dataImport.dwDataSize, szShareName);

  if (dataLocal.hSharedMemory) {
    LPVOID lpSharedMem = MapViewOfFile(
        dataLocal.hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, dataImport.dwDataSize);

    // Generate data buffer
    PBYTE lpCurrent = (PBYTE)lpSharedMem;
    for (const auto& it_module : dataImport.modules) {
      memcpy(lpCurrent, it_module.c_str(), it_module.size() + 1);
      lpCurrent += it_module.size() + 1;
      if (dataImport.functions.at(it_module).size()) {
        // Add delimiter (0x1F)
        *lpCurrent = (BYTE)0x1F;
        lpCurrent++;

        for (const auto& it_func : dataImport.functions.at(it_module)) {
          memcpy(lpCurrent, it_func.c_str(), it_func.size() + 1);
          lpCurrent += it_func.size() + 1;
        }

        *lpCurrent = (BYTE)0x1F;
        lpCurrent++;
      }
    }

    UnmapViewOfFile(lpSharedMem);

    return dataImport.dwDataSize;
  }

  return 0;
}

C_EXPORT BOOL freeSharedMemory() noexcept {
  if (dataLocal.hSharedMemory) {
    CloseHandle(dataLocal.hSharedMemory);
    return TRUE;
  }

  return FALSE;
}

C_EXPORT void ejectDLL() noexcept {
  FreeLibraryAndExitThread(GetModuleHandleA("hklib.dll"), 0);
}
