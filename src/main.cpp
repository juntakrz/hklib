#include "pch.h"
#include "define.h"
#include "util.h"
#include "CFileProc.h"
#include "CBufferProc.h"
#include "mainFuncs.h"

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