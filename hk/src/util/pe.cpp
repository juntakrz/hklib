#include "../pch.h"
#include "../define.h"
#include "../dataStruct.h"
#include "util.h"
#include "pe.h"

bool hk_pe::readPEHeaderData(BYTE* buffer) noexcept {
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
  PEData.pSecHdr = IMAGE_FIRST_SECTION(PEData.pNTHdr);

  LOG("PE header data retrieved.");

  return true;
}

bool hk_pe::readPEExportData(BYTE* buffer) noexcept { return true; }

bool hk_pe::readPEImportData(BYTE* buffer) noexcept {
  LOGn("Parsing PE import data...");

  if (!PEData.pDOSHdr || !PEData.pNTHdr || !PEData.pSecHdr) {
    LOG("Failure. Empty or corrupt PE header data.");                       // don't forget about executing readPEHeaderData first
    return false;
  }

  if (PEData.pImportDir->Size > 0) {
    dataImport.clear();
    PIMAGE_IMPORT_DESCRIPTOR pIDescIt = PIMAGE_IMPORT_DESCRIPTOR(
        (PBYTE)PEData.pDOSHdr +
        hk_util::RVAToOffset(PEData.pNTHdr, PEData.pImportDir->VirtualAddress));
    
    while (pIDescIt->Characteristics != 0) {
      // retrieve module/library name
      LPSTR libName = (PCHAR)PEData.pDOSHdr +
                      hk_util::RVAToOffset(PEData.pNTHdr, pIDescIt->Name);
      dataImport.modules.emplace_back(libName);

      // retrieve all functions in the import table for the current module
      dataImport.functionsEx.try_emplace(libName);
      
      // parsing image lookup table to get function names
      PIMAGE_THUNK_DATA pThunkILT = PIMAGE_THUNK_DATA(
          (PBYTE)PEData.pDOSHdr +
          hk_util::RVAToOffset(PEData.pNTHdr, pIDescIt->OriginalFirstThunk));

      PIMAGE_IMPORT_BY_NAME pIBName = nullptr;

      while (pThunkILT->u1.AddressOfData != 0) {
        // not ordinal
        if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
          pIBName = PIMAGE_IMPORT_BY_NAME(
              (PBYTE)PEData.pDOSHdr +
              hk_util::RVAToOffset(PEData.pNTHdr, pThunkILT->u1.Function));

          //dataImport.functionsEx.at(libName).emplace_back({ pIBName->Name,  })
        }
      }
    }
  }

  LOG("\t\t\tFailure. No import data found.");
  return false;
}
