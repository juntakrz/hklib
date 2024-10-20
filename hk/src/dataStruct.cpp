#include "pch.h"
#include "appf.h"
#include "datastruct.h"

DTGlobal global;
DTImport dataImport;

BOOL DTGlobal::addFunction(LPCSTR function) noexcept {
  if (remoteFunctions.try_emplace(function).second) {
    remoteFunctions.at(function) = 0;
    return true;
  }

  return false;
}

BOOL DTGlobal::removeFunction(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.erase(function);
    return true;
  }

  return false;
}

BOOL DTGlobal::storeOffset(LPCSTR function, DWORD offset) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.at(function) = offset;
    return true;
  }

  return false;
}

void DTGlobal::updateOffsets() noexcept {
  for (auto& it : remoteFunctions) {
    it.second = hk_dll::getExportOffset(it.first.c_str());
  }
}

DWORD DTGlobal::offsetOf(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    return remoteFunctions.at(function);
  }

  LOG(logError, "function '%s' was not found in the database.", function);

  return -1;
}

void DTImport::clear() noexcept {
  modules.clear();
  functions.clear();
}