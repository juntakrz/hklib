#pragma once

#include "define.h"

//
// dllfunc_PE.cpp
//

// Analyze PE image of a host and fill the database
void analyzePEImage() noexcept;

// Parse PE import descriptor for a given module
void parseImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, const std::string& libraryName) noexcept;

//
// dllfunc_payload.cpp
//

// Get IAT entry for a required module and function
LPVOID getIATEntry(const std::string& libraryName, const std::string& functionName) noexcept;

// Replace IAT entry with an address of another function
void replaceIATEntry(LPVOID lpSource, LPVOID lpTarget) noexcept;

// Main payload function
void hijack() noexcept;

// dllfunc_util.cpp
void createConsole() noexcept;
void outputPEDataToConsole() noexcept;
std::string serializeAddressToString(PBYTE pAddress);
std::string serializeOffsetToString(uint64_t offset);
bool serializeAnalysisDataToMemory();

//
// dllfunc_export.cpp
//

// Export PE image data to the controller
C_EXPORT DWORD exportPEImageData() noexcept;

// Free shared memory allocated when exporting data
C_EXPORT BOOL freeSharedMemory() noexcept;
C_EXPORT void ejectDLL() noexcept;