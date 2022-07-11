#include "pch.h"
#include "mainFuncs.h"

void printHelp() noexcept {
  LOG("USAGE: hk [process id] [-argument]");
  LOG("Arguments:\n  -i\t\tinject hklib.dll");
  LOG("  -a\t\tanalyze process and output its import data");
  LOG("  -s\t\tless verbose output of import data analysis");
  LOG("\nEXAMPLE: hk 1377 -i");
  LOG("\nPress ANY key to exit.");
  _getch();

  exit(0);
}

int processArgs(int argc, wchar_t* argv[]) {
  
  DWORD procID = 0;
  appMode mode = appMode::none;
  std::vector<std::wstring> argList;
  bool isDetailed = true;

  for (int i = 1; i < argc; i++) {
    argList.emplace_back(argv[i]);
  }

  procID = stoi(argList[0]);

  // basic argument parser
  for (uint8_t args = 1; args < argList.size(); args++) {
     
    if (argList[args] == L"-a") {
      mode = appMode::analyze;
    }

    if (argList[args] == L"-i") {
      mode = appMode::inject;
    }

    if (argList[args] == L"-s") {
      isDetailed = false;
    }
  }

  switch (mode) {
    case appMode::analyze : {
      CBufferProc buffer;
      buffer.attach(procID);
      return 0;
    }
    case appMode::inject : {
      return inject(procID);
    }
  }

  printHelp();

  return 0;
};

void presentResults(CBufferProc* execBuffer,
                    bool isDetailed) noexcept {

  HMODULE hLib = nullptr;
  std::string loadedLibName = "";

  // library index, winapi functions num, total functions num, winapi libraries
  // num, functions containing "w" num
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

  if (!execBuffer->libs().empty()) {
    LOG("\nLibraries in the import table:\n");

    // show every imported library found
    for (const auto& it_lib : execBuffer->libs()) {
      LOG(index << ".\t" << it_lib);

      // show every imported function found per library
      // requires -d command line argument
      (isDetailed) ? LOG("\t   \\") : std::cout;

      findResult =
          (execBuffer->funcs().find(it_lib) != execBuffer->funcs().end());

      if (!execBuffer->funcs().empty() && findResult) {
        for (const auto it_func : execBuffer->funcs().at(it_lib)) {
          query = isWinAPI(it_lib, it_func);

          if (isDetailed) {
            (query) ? LOG("\t*  |= " << it_func) : LOG("\t   |= " << it_func);
          }
        }
      }

      totalCount += (findResult) ? execBuffer->funcs().at(it_lib).size() : 0u;
      index++;
    }

    (isDetailed) ? LOG("\n* - WinAPI method.") : std::cout;
  }
    LOG("\nREPORT:\n");

  if (!execBuffer->libs().empty()) {
    LOG("WinAPI libraries detected: " << wLibCount << " out of "
                                   << execBuffer->libs().size() << ".");
    LOG("WinAPI methods detected: " << wCount << " out of " << totalCount << ".\n");
  }
  /*
  wLOG("Entropy for '" << execBuffer->getSource()->getFilePath()
                        << "': " << execBuffer->getSource()->getEntropy());*/

}

int inject(const DWORD& procID) noexcept {

  // init variables
  HANDLE hProc = nullptr;
  HANDLE hRThread = nullptr;
  DWORD idRThread = 0;
  HMODULE hKernel = nullptr;
  LPTHREAD_START_ROUTINE LLAddr = nullptr;
  LPVOID lpBaseAddr = nullptr;
  SIZE_T bytesWritten = 0;
  //const char* dllPath = "c:\\Users\\krz\\Desktop\\hklib.dll";
  const char* dllPath = "hklib.dll";
  std::string fullPath = "";

  std::string moduleName = "kernel32";
  std::string funcName = "LoadLibraryA";

  {
    char buffer[MAX_PATH] = {};
    GetFullPathNameA(dllPath, MAX_PATH, buffer, nullptr);
    fullPath = std::string(buffer);
  }

  printf("Opening process (PID %d)...\t", procID);

  if (!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID))) {
    printf("Failure.\n");
    ERRCHK;
  }

  printf("Success.\nPID %d, instance: 0x%p\n", procID, hProc);

  if (!(hKernel = GetModuleHandleA(moduleName.c_str()))) {
    printf("'%s' is not loaded by the process.\n", moduleName.c_str());
    ERRCHK;
  }

  printf("Library '%s' at 0x%p\n", moduleName.c_str(), hKernel);

  if (!(LLAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, funcName.c_str()))) {
    printf("Failed to detect '%s' in memory.\n", funcName.c_str());
    ERRCHK;
  }

  printf("Function '%s\\%s' at 0x%p\n", moduleName.c_str(), funcName.c_str(), LLAddr);

  if (!(lpBaseAddr = VirtualAllocEx(hProc, NULL, fullPath.size(), MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE))) {
    printf("Failed to allocate additional memory for PID %p.\n", hProc);
    ERRCHK;
  }

  printf("Allocated %zu bytes for sending dll path at 0x%p\nWriting memory...\t\t", fullPath.size(), lpBaseAddr);

  if (!(WriteProcessMemory(hProc, lpBaseAddr, (LPCVOID)fullPath.c_str(),
                               fullPath.size(), &bytesWritten))) {
    printf("Failure.\n");
    ERRCHK;
  }

  printf("Success.\nInjected dll path '%s' (%llu bytes) at %p in process ID %d.\n",
            fullPath.c_str(), bytesWritten, lpBaseAddr, procID);

  if (!(hRThread = CreateRemoteThread(hProc, nullptr, NULL, LLAddr,
                                      lpBaseAddr, NULL, &idRThread))) {
    ERRCHK;
  };

  printf("Created remote thread (ID %d)\n", idRThread);

  WaitForSingleObject(hRThread, INFINITE);

  printf("\nPress ANY key to exit.\n");

  _getch();

  if (hProc) {
    VirtualFreeEx(hProc, lpBaseAddr, 0, MEM_RELEASE);
    CloseHandle(hProc);
  }

  return 0;
}