#include "pch.h"
#include "CFileProc.h"
#include "CBufferProc.h"
#include "mainFuncs.h"

void printHelp() noexcept {
  LOG("USAGE: tie [path_to_executable]");
  LOG("Arguments:\n  -i [path_to_icon]\t.ico file to replace original icon "
      "with");
  LOG("  -o [output_filename]\toutput .exe file, will write to the same "
      "executable if not defined");
  LOG("  -s\t\t\tshort report");
  LOG("\nEXAMPLE: tie test.exe -o test_copy.exe -i icon1.ico");

  exit(0);
}

void processArgs(int argc, wchar_t* argv[]) {

  std::vector<std::wstring> argList;
  std::wstring iconPath = L"", outputPath = L"";
  CFileProc fIcon;
  bool isDetailed = true;

  for (int i = 1; i < argc; i++) {
    argList.emplace_back(argv[i]);
  }

  // basic argument parser
  for (uint8_t args = 1; args < argList.size(); args++) {
    if (argList[args] == L"-i" && argList.size() > args) {
      iconPath = argList[args + 1];
      args++;  // skip next argument
    }

    if (argList[args] == L"-o" && argList.size() > args) {
      outputPath = argList[args + 1];
      args++;  // skip next argument
    }

    if (argList[args] == L"-s") {
      isDetailed = false;
    }
  }

  CFileProc fExec(argList[0]);
  CBufferProc bExec(&fExec);
  fExec.calcEntropy();

   bExec.parseExecHeader();

  if (iconPath != L"") {
    fIcon.openFile(iconPath);
    fIcon.calcEntropy();
    bExec.injectIcon(&fIcon, outputPath.c_str());
  }
  
  presentResults(&bExec, &fIcon, isDetailed);
};

void presentResults(CBufferProc* execBuffer, CFileProc* iconFile,
                    bool isDetailed) noexcept {

  HMODULE hLib = nullptr;
  std::string loadedLibName = "";

  // library index, winapi functions num, total functions num, winapi libraries
  // num, functions containing "w" num
  size_t index = 0, wCount = 0, totalCount = 0, wLibCount = 0, wNamed = 0;
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

      // detect if any function has W in its name
      if (funcName.find('W') != std::string::npos ||
          funcName.find('w') != std::string::npos) {
        wNamed++;
      }

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
    LOG("WinAPI methods detected: " << wCount << " out of " << totalCount
                                 << ", of these " << wNamed << " contain 'w'.\n");
  }

  wLOG("Entropy for '" << execBuffer->getSource()->getFilePath()
                        << "': " << execBuffer->getSource()->getEntropy());

  if (iconFile) {
    wLOG("Entropy for '" << iconFile->getFilePath()
                          << "': " << iconFile->getEntropy());
  }

}