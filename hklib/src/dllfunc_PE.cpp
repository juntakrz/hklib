#include "pch.h"
#include "dllfunc.h"

void parseImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, const std::string& libraryName) noexcept {
  if (!pImportDesc || libraryName.empty()) {
    return;
  }

  std::vector<std::string> collectedFuncs;

  PIMAGE_THUNK_DATA pThunkILT = nullptr;
  PIMAGE_THUNK_DATA pThunkIAT = nullptr;
  PIMAGE_IMPORT_BY_NAME pIBName = nullptr;

  pThunkILT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHeader + pImportDesc->OriginalFirstThunk);
  pThunkIAT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHeader + pImportDesc->FirstThunk);

  std::stringstream sstr;

  while (pThunkILT->u1.AddressOfData != 0) {
      
    sstr.clear();
    sstr.str(std::string());

    if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
      pIBName = PIMAGE_IMPORT_BY_NAME((PBYTE)dataLocal.pDOSHeader + pThunkILT->u1.AddressOfData);
      uint64_t functionOffsetFromBase = (uint64_t)pThunkIAT->u1.Function - (uint64_t)dataLocal.pBaseAddress;
      sstr << pIBName->Name << "*" << serializeOffsetToString(functionOffsetFromBase);
      collectedFuncs.emplace_back(sstr.str());
    }
    else if (IMAGE_ORDINAL(pThunkILT->u1.Ordinal)) {
      uint64_t functionOffsetFromBase = (uint64_t)pThunkIAT->u1.Function - (uint64_t)dataLocal.pBaseAddress;
      sstr << "<Ordinal> " << (pThunkILT->u1.Function & 0xffff);// << "*" << serializeOffsetToString(functionOffsetFromBase);
      collectedFuncs.emplace_back(sstr.str());
    }
    pThunkILT++;
    pThunkIAT++;
  }

  if (!collectedFuncs.empty()) {
    if (dataImport.functions.try_emplace(libraryName).second) {
      dataImport.functions.at(libraryName) = std::move(collectedFuncs);
    }
  }
}

void analyzePEImage() noexcept {

  dataImport.modules.clear();
  dataImport.functions.clear();

  dataLocal.pDOSHeader = (PIMAGE_DOS_HEADER)dataLocal.pBaseAddress;

  if (dataLocal.pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return;
  }

  dataLocal.pNTHeader = PIMAGE_NT_HEADERS((PBYTE)dataLocal.pDOSHeader + dataLocal.pDOSHeader->e_lfanew);

  if (dataLocal.pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
    return;
  }

  dataLocal.pOptionalHeader = &dataLocal.pNTHeader->OptionalHeader;
  PIMAGE_DATA_DIRECTORY pDataDirectory = &dataLocal.pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (pDataDirectory->Size > 0) {
    PIMAGE_IMPORT_DESCRIPTOR pBaseImportDesc = PIMAGE_IMPORT_DESCRIPTOR((PBYTE)dataLocal.pBaseAddress + pDataDirectory->VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR pItImportDesc = pBaseImportDesc;

    while (pItImportDesc->Characteristics != NULL) {
      LPSTR pLibraryName = (PCHAR)dataLocal.pDOSHeader + pItImportDesc->Name;
      dataImport.modules.emplace_back(pLibraryName);
      parseImportDescriptor(pItImportDesc, pLibraryName);
      pItImportDesc++;
    }
  }
}