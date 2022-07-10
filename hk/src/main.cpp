#include "pch.h"
#include "define.h"
#include "mainFuncs.h"

int wmain(int argc, wchar_t *argv[]) { 
  
  DWORD procID = 0;

  LOG("LOG:\n");

  if (argc > 1) {
    return processArgs(argc, argv);
  }

  LOG("ERROR: No process ID was provided.\n");
  printHelp();
  _getch();

  return 0;
}