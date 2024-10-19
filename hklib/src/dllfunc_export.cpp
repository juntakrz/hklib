#include "pch.h"
#include "dllfunc.h"

C_EXPORT DWORD exportPEImageData() noexcept {
  analyzePEImage();

  if (serializeAnalysisDataToMemory()) {
    return dataImport.dwDataSize;
  }

  return -1;
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
