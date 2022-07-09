#include "pch.h"
#include "appf.h"
#include "dataStruct.h"

SGlobalData global;
SImportData dataImport;

BOOL SGlobalData::addFunction(LPCSTR function) noexcept {
  if (remoteFunctions.try_emplace(function).second) {
    remoteFunctions.at(function) = 0;
    return true;
  }

  return false;
}

BOOL SGlobalData::removeFunction(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.erase(function);
    return true;
  }

  return false;
}

BOOL SGlobalData::storeOffset(LPCSTR function, DWORD offset) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    remoteFunctions.at(function) = offset;
    return true;
  }

  return false;
}

void SGlobalData::updateOffsets() noexcept {
  for (auto& it : remoteFunctions) {
    it.second = getDLLExportOffset(it.first.c_str());
  }
}

DWORD SGlobalData::offsetOf(LPCSTR function) noexcept {
  if (remoteFunctions.find(function) != remoteFunctions.end()) {
    return remoteFunctions.at(function);
  }

  LOG("ERROR: function '" << function << "' not found in the database.");

  return -1;
}
