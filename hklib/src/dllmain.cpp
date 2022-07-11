#include "pch.h"
#include "define.h"

EXPORT BOOL APIENTRY
    DllMain(HINSTANCE hInst, DWORD fdwReason, LPVOID lpReserved) {

  switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
      MessageBoxA(0, "This program just got injected with a DLL.", "SUCCESS", MB_OK | MB_ICONINFORMATION);
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