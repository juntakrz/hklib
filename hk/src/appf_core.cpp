#include "pch.h"
#include "appf.h"
#include "dataStruct.h"

void printHelp() noexcept {
  LOG("USAGE:  hk [process name / id] [-arguments]\n");
  LOG("Arguments:");
  LOG("  -a\t\tanalyze the process and output the data");
  LOG("\nEXAMPLE: hk -p notepad.exe\tinject into notepad.exe");
  LOG("\t hk -pid 1377\t\tinject into process with PID 1377");
  LOG("\nPress ANY key to exit.");
  _getch();

  exit(0);
}

int parseArgs(int argc, wchar_t* argv[]) {
  
  global.dllName = L"hklib.dll";

  DWORD PID;
  std::vector<std::wstring> argList;
  const std::wregex rNumbers(L"0-9");

  for (int i = 1; i < argc; i++) {
    argList.emplace_back(argv[i]);
  }

  if(!std::regex_match(argList[0].begin(), argList[0].end(), rNumbers)) {
    PID = getProcessID(argList[0].c_str());
  } else {
    PID = wcstol(argList[0].c_str(), nullptr, 10);
  }

  dllInject(PID);

  wchar_t arg = 0;
  for (int j = 1; j < argList.size(); j++) {
    // arguments are in '-X' format, so ignore '-'
    if (argList[j].size() > 1) {
      arg = *(argList[j].c_str() + 1);
      switch (arg) {
        case 'a': {
          analyzeTarget();
          presentResults();
          break;
        }
      }
    }
  }

  LOG("\nPress ANY key to exit.");
  _getch();
  dllEject();
  return 0;
};

void analyzeTarget() noexcept {
  // init values
  DWORD idThread = 0;

  global.dllBaseAddr = getDLLBaseAddr();
  global.addFunction("exportPEImageData");
  global.addFunction("freeSharedMemory");
  global.updateOffsets();

  HANDLE hExportThread = NULL;
  DWORD dwDataSize = dllCall("exportPEImageData", hExportThread, NULL_ID, CALL_NO_CLOSE);

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

    dllCall("freeSharedMemory", NULL_THREAD, NULL_ID, 0);
  }
  CloseHandle(hExportThread);
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