#include "pch.h"
#include "define.h"
#include "util.h"
#include "CFileProc.h"
#include "CBufferProc.h"
#include "mainFuncs.h"

/*
int wmain(int argc, wchar_t* argv[]) {
  
  LOG("HKLIB\n");

  if (argc < 2 || argc > 7) {
    //printHelp();
  }
  else {
	processArgs(argc, argv);
  }

  LOG("\nAll done. Press ENTER to exit...");
  std::cin.get();
  return 0;
}
*/

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