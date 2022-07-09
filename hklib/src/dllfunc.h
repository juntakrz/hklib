#pragma once

#include "define.h"

// dllfunc_PE.cpp
void analyzePEImage() noexcept;                                             // analyze PE image of a host and fill the database
void parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc,
                       std::string libName) noexcept;                       // parse PE import descriptor for a given module

// dllfunc_payload.cpp
LPVOID getIATEntry(std::string libName, std::string funcName) noexcept;     // get IAT entry for a required module and function
void replaceIATEntry(LPVOID source, LPVOID target) noexcept;                // replace IAT entry with an address of another function
void hijack() noexcept;                                                     // main payload function

// dllfunc_util.cpp
void createConsole() noexcept;
void outputPEDataToConsole() noexcept;

// dllfunc_export.cpp
C_EXPORT DWORD  exportPEImageData() noexcept;                               // export PE image data to the controller
C_EXPORT BOOL   freeSharedMemory() noexcept;                                // free shared memory allocated when exporting data
C_EXPORT void   ejectDLL() noexcept;