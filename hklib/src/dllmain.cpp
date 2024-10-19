#include "pch.h"
#include "define.h"
#include "dllfunc.h"

DATA_IMPORT dataImport;
DATA_LOCAL  dataLocal;

void init(HINSTANCE hInst) noexcept {
  // get base address of the host
  dataLocal.pBaseAddress = (PBYTE)GetModuleHandleA(NULL);
  LPVOID pFunc0 = getIATEntry("GDI32.dll", "GetPixel");
  replaceIATEntry(pFunc0, hijack);
}

EXPORT BOOL APIENTRY
    DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {

  switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
      init(hInst);
      break;
    }
    case DLL_THREAD_ATTACH: {
      break;
    }
    case DLL_THREAD_DETACH: {
      break;
    }
    case DLL_PROCESS_DETACH: {
      break;
    }
  }

  return TRUE;
}