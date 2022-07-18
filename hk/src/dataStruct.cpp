#include "pch.h"
#include "appf.h"
#include "datastruct.h"

dtGlobal global;
dtImport dataImport;

BOOL dtGlobal::addFunction(LPCSTR function) noexcept {
  if (remoteFunctions.try_emplace(function).second) {
    remoteFunctions.at(function) = 0;
    return true;
  }

  return false;
}

BOOL dtGlobal::removeFunction(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.erase(function);
    return true;
  }

  return false;
}

BOOL dtGlobal::storeOffset(LPCSTR function, DWORD offset) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.at(function) = offset;
    return true;
  }

  return false;
}

void dtGlobal::updateOffsets() noexcept {
  for (auto& it : remoteFunctions) {
    it.second = hk_dll::getExportOffset(it.first.c_str());
  }
}

DWORD dtGlobal::offsetOf(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    return remoteFunctions.at(function);
  }

  LOG("ERROR: function '" << function << "' not found in the database.");

  return -1;
}

void dtImport::clear() noexcept {
  modules.clear();
  functions.clear();
}