#include "pch.h"
#include "dllfunc.h"

C_EXPORT DWORD exportPEImageData() noexcept {
  // analize current PE image
  analyzePEImage();

  const char* szShareName = "%HKDATA%";

  // calculate size of resulting data
  dataImport.dwDataSize = 0;

  for (const auto& it_module : dataImport.modules) {
    dataImport.dwDataSize += (DWORD)it_module.size() + 1;

    if (it_module.size()) {
      dataImport.dwDataSize++;  // add one byte for delimiter
      for (const auto& it_func : dataImport.functions.at(it_module)) {
        dataImport.dwDataSize += (DWORD)it_func.size() + 1;
      }
      dataImport.dwDataSize++;  // add one byte for delimiter
    }
  }

  dataLocal.hSharedMem =
      CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                         dataImport.dwDataSize, szShareName);

  if (dataLocal.hSharedMem) {
    LPVOID lpSharedMem = MapViewOfFile(
        dataLocal.hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, dataImport.dwDataSize);

    // generate data buffer
    PBYTE lpCurrent = (PBYTE)lpSharedMem;
    for (const auto& it_module : dataImport.modules) {
      memcpy(lpCurrent, it_module.c_str(), it_module.size() + 1);
      lpCurrent += it_module.size() + 1;
      if (dataImport.functions.at(it_module).size()) {
        // add delimiter (0x1F)
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
  if (dataLocal.hSharedMem) {
    CloseHandle(dataLocal.hSharedMem);
    return TRUE;
  }

  return FALSE;
}

C_EXPORT void ejectDLL() noexcept {
  FreeLibraryAndExitThread(GetModuleHandleA("hklib.dll"), 0);
}
