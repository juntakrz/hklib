#include "pch.h"
#include "define.h"

EXPORT void dasInjector() noexcept;

BOOL WINAPI DLLMain (HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpReserver){

  //
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
      dasInjector();
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

EXPORT void dasInjector() noexcept {
  MessageBoxA(nullptr, "Hooked", "Important message", MB_OK);
}