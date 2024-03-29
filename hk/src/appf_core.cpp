#include "pch.h"
#include "appf.h"
#include "dataStruct.h"

void printHelp() noexcept {
  LOG("USAGE:  hk [process name / id] [-arguments]\n");
  LOG("Arguments:");
  LOG("  -a\t\tanalyze the process and output the data");
  LOG("  -h\t\thollow out the process and inject the test code");
  LOG("\nEXAMPLE: hk notepad.exe\tinject into notepad.exe");
  LOG("\t hk 1377 -a\t\tinject into process with PID 1377 and retrieve its data");
  LOG("\nPress ANY key to exit.");
  _getch();

  exit(0);
}

int parseArgs(int argc, wchar_t* argv[]) {
  
  if (argc < 2) {
    printHelp();
  }

  global.dllName = L"hklib.dll";

  DWORD PID;
  const std::wregex rNumbers(L"0-9");
  std::wstring processArg(argv[1]);

  if (!std::regex_match(processArg.begin(), processArg.end(), rNumbers)) {
    PID = getProcessID(processArg.c_str());
  } else {
    PID = wcstol(processArg.c_str(), nullptr, 10);
  }

  wchar_t** pCurrentArg = argv + 2;
  wchar_t arg = 0;
  while(*pCurrentArg) {
    // arguments are in '-X' format, so skip '-'
    arg = *(*pCurrentArg + 1);
    switch (arg) {
      case 'a': {
        hk_dll::inject(PID);
        analyzeTarget();
        presentResults();
        break;
      }
      case 'h': {
        hk_local::hollowTarget(PID);
        break;
      }
      case 't': {
        testShellCode();
        break;
      }
      default: {
        hk_dll::inject(PID);
        break;
      }
    }

    pCurrentArg++;
  }

  LOG("\nPress ANY key to exit.");
  _getch();
  hk_dll::eject();      // safe - ignored if DLL wasn't injected
  return 0;
};

void analyzeTarget() noexcept {
  // init values
  DWORD idThread = 0;

  global.dllBaseAddr = hk_dll::getBaseAddr();
  global.addFunction("exportPEImageData");
  global.addFunction("freeSharedMemory");
  global.updateOffsets();

  HANDLE hExportThread = NULL;
  DWORD dwDataSize =
      hk_dll::call("exportPEImageData", hExportThread, NULL_ID, CALL_NO_CLOSE);

  LOG("Receiving " << dwDataSize << " bytes of data gathered inside the host.");

  HANDLE hSharedMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, false, "%HKDATA%");
  if (hSharedMem) {
    LPVOID lpView =
        MapViewOfFile(hSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, dwDataSize);

    std::vector<std::string> modules;
    std::map<std::string, std::vector<std::string>> functions;

    PBYTE pCurrent = (PBYTE)lpView;

    for (DWORD m = 0; m < dwDataSize;) {
      modules.emplace_back((char*)pCurrent + m);
      m += modules.back().size() + 1;

      // 0x1F = delimiter
      if (*(pCurrent + m) == (BYTE)0x1F) {
        m++;
        while (*(pCurrent + m) != (BYTE)0x1F) {
          functions[modules.back()].emplace_back((char*)pCurrent + m);
          m += functions.at(modules.back()).back().size() + 1;
        };
        m++;
      }
    }

    dataImport.modules.clear();
    dataImport.functions.clear();
    dataImport.modules = std::move(modules);
    dataImport.functions = std::move(functions);

    CloseHandle(hSharedMem);

    hk_dll::call("freeSharedMemory", NULL_THREAD, NULL_ID, 0);
  }
  CloseHandle(hExportThread);
}

void testShellCode() noexcept {
    
  LOG("Testing provided shellcode (hex):");
  
  // return x + y * x + y / 100
  /*BYTE shellCode[] = {0x44, 0x8D, 0x42, 0x01, 0xB8, 0x1F, 0x85, 0xEB,
                       0x51, 0xF7,
                    0xEA, 0x44, 0x0F, 0xAF, 0xC1, 0xC1, 0xFA, 0x05, 0x8B, 0xC2,
                    0xC1, 0xE8, 0x1F, 0x41, 0x03, 0xD0, 0x03, 0xC2, 0xC3, 0x00};
                    */

  for (size_t i = 0; i < hk_util::shellCodeSize; i++) {
    std::cout << std::hex << std::uppercase << ((*(hk_util::shellCode + i) < 16) ? "0" : "") << +*(hk_util::shellCode + i) << " ";
  }
  std::cout << std::dec << "\n\n";

  int x = 5, y = 1000;
  void* exec =
      VirtualAlloc(0, hk_util::shellCodeSize, MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE);
  memcpy(exec, hk_util::shellCode, hk_util::shellCodeSize);
  /*int result =
      ((int (*)(int, int))exec)(x, y);  // that C/C++ function casting, oh boy

  LOG("x = " << x << ", y = " << y << ".\n" << "x + y * x + y / 100 = " << result);
  */

  //((void(*)())exec)();
  using shCodeExec = void(*)();
  ((shCodeExec)exec)();
}

void presentResults() noexcept {
  HMODULE hLib = nullptr;
  std::string loadedLibName = "";

  // library index, winapi functions num, total functions num, winapi libraries num
  size_t index = 0, wCount = 0, totalCount = 0, wLibCount = 0;
  bool query = false, findResult = false;

  // WinAPI function detection, returns true if GetProcAddress isn't null
  auto isWinAPI = [&](const std::string& libName, const std::string& funcName) {
    if (libName != loadedLibName) {
      if (hLib) {
        FreeLibrary(hLib);
      }

      hLib = LoadLibraryA(libName.c_str());

      if (hLib) {
        wLibCount++;
        loadedLibName = libName;
      }
    }

    if (hLib && GetProcAddress(hLib, funcName.c_str())) {
      wCount++;
      return true;
    }

    return false;
  };

  if (!dataImport.modules.empty()) {
    LOG("\nLibraries in the import table:\n");

    // show every imported library found
    for (const auto& it_module : dataImport.modules) {
      LOG(index << ".\t" << it_module);
      LOG("\t   \\");

      findResult =
          (dataImport.functions.find(it_module) != dataImport.functions.end());

      if (!dataImport.functions.empty() && findResult) {
        for (const auto it_func : dataImport.functions.at(it_module)) {
          query = isWinAPI(it_module, it_func);
          query ? LOG("\t*  |= " << it_func) : LOG("\t   |= " << it_func);
        }
      }

      totalCount += (findResult) ? dataImport.functions.at(it_module).size() : 0u;
      index++;
    }

    LOG("\n* - WinAPI method.");
  }
  LOG("\nREPORT:\n");

  if (!dataImport.modules.empty()) {
    LOG("WinAPI libraries detected: " << wLibCount << " out of "
                                      << dataImport.modules.size() << ".");
    LOG("WinAPI methods detected: " << wCount << " out of " << totalCount
                                    << ".\n");
  }
  /*
  wLOG("Entropy for '" << execBuffer->getSource()->getFilePath()
                        << "': " << execBuffer->getSource()->getEntropy());*/
}