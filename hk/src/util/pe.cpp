#include "../pch.h"
#include "../define.h"
#include "../dataStruct.h"
#include "pe.h"

bool util_pe::readPEHeaderData(BYTE* buffer) noexcept {
  LOG("Reading PE header data from the provided buffer.");
  PEData.pDOSHdr = PIMAGE_DOS_HEADER(buffer);
  if (PEData.pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE) {
    LOG("ERROR: buffer is not of PE type. Read PE Data Error 1.");
    return false;
  }

  PEData.pNTHdr = PIMAGE_NT_HEADERS((PBYTE)PEData.pDOSHdr + PEData.pDOSHdr->e_lfanew);

  if (PEData.pNTHdr->Signature != IMAGE_NT_SIGNATURE) {
    LOG("ERROR: buffer is not of PE type. Read PE Data Error 2.");
    return false;
  }

  PEData.isDLL = PEData.pNTHdr->FileHeader.Characteristics & (1 << 14);     // 14th bit test, which, if set, means it's a DLL

  PEData.pExportDir = (PIMAGE_EXPORT_DIRECTORY)&PEData.pNTHdr->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  PEData.pImportDir = (PIMAGE_DATA_DIRECTORY)&PEData.pNTHdr->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  LOG("PE header data retrieved.");

  return true;
}

bool util_pe::readPEExportData(BYTE* buffer) noexcept { return false; }

bool util_pe::readPEImportData(BYTE* buffer) noexcept { return false; }
