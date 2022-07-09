#include "pch.h"
#include "define.h"
#include "appf.h"

int wmain(int argc, wchar_t *argv[]) { 

  LOG("<HK> LOG\n");

  if (argc > 1) {
    return parseArgs(argc, argv);
  }

  printHelp();
  _getch();

  return 0;
}