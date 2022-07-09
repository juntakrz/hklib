#include "pch.h"
#include "dllfunc.h"

void createConsole() noexcept {
  if (AllocConsole()) {
    FILE* fDummyCon;
    freopen_s(&fDummyCon, "CONOUT$", "w", stdout);
    freopen_s(&fDummyCon, "CONIN$", "w", stdin);
    freopen_s(&fDummyCon, "CONOUT$", "w", stderr);
    std::cout.clear();
    std::cin.clear();
    std::cerr.clear();
    std::clog.clear();
  }
}

void outputPEDataToConsole() noexcept {
  std::stringstream sstr;
  sstr << "Base address: 0x" << dataLocal.pBaseAddr << "\n\n";
  for (const auto& it_lib : dataImport.modules) {
    sstr << it_lib << ":\n";
    for (const auto& it_func : dataImport.functions.at(it_lib)) {
      sstr << "\t" << it_func << "\n";
    }
    sstr << "\n";
  }

  std::cout << sstr.str();
}