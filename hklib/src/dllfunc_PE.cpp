#include "pch.h"
#include "dllfunc.h"

void parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, std::string libName) noexcept {
  if (pImportDesc && libName != "") {

    std::vector<std::string> collectedFuncs;

    PIMAGE_THUNK_DATA pThunkILT = nullptr;
    PIMAGE_THUNK_DATA pThunkIAT = nullptr;
    PIMAGE_IMPORT_BY_NAME pIBName = nullptr;

    pThunkILT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHdr +
                                           pImportDesc->OriginalFirstThunk);
    pThunkIAT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHdr + pImportDesc->FirstThunk);

    std::stringstream sstr;

    while (pThunkILT->u1.AddressOfData != 0) {
      
      sstr.clear();
      sstr.str(std::string());

      if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
        pIBName =
            PIMAGE_IMPORT_BY_NAME((PBYTE)dataLocal.pDOSHdr + pThunkILT->u1.AddressOfData);

        sstr << pIBName->Name;// << " __ 0x" << std::uppercase << std::hex << uint64_t((PBYTE)pThunkIAT->u1.Function);
        collectedFuncs.emplace_back(sstr.str());
      } else if (IMAGE_ORDINAL(pThunkILT->u1.Ordinal)) {

        sstr << "<Ordinal> " << std::dec << (pThunkILT->u1.Function & 0xffff);// << " __ 0x" << std::uppercase << std::hex << uint64_t((PBYTE)pThunkIAT->u1.Function);
        collectedFuncs.emplace_back(sstr.str());
      }
      pThunkILT++;
      pThunkIAT++;
    }

    if (!collectedFuncs.empty()) {
      if (dataImport.functions.try_emplace(libName).second) {
        dataImport.functions.at(libName) = std::move(collectedFuncs);
      }
    }
  }
}

void analyzePEImage() noexcept {

  dataImport.modules.clear();
  dataImport.functions.clear();

  dataLocal.pDOSHdr = (PIMAGE_DOS_HEADER)dataLocal.pBaseAddr;

  if (dataLocal.pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE) {

    dataLocal.pNTHdr =
        PIMAGE_NT_HEADERS((PBYTE)dataLocal.pDOSHdr + dataLocal.pDOSHdr->e_lfanew);

    if (dataLocal.pNTHdr->Signature == IMAGE_NT_SIGNATURE) {
      dataLocal.pOptHdr = &dataLocal.pNTHdr->OptionalHeader;

      PIMAGE_DATA_DIRECTORY pDataDir =
          &dataLocal.pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

      if (pDataDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pBaseImportDesc = PIMAGE_IMPORT_DESCRIPTOR(
            (PBYTE)dataLocal.pBaseAddr + pDataDir->VirtualAddress);

        PIMAGE_IMPORT_DESCRIPTOR pItImportDesc = pBaseImportDesc;

        while (pItImportDesc->Characteristics != NULL) {
          LPSTR pLibName = (PCHAR)dataLocal.pDOSHdr + pItImportDesc->Name;
          dataImport.modules.emplace_back(pLibName);
          parseImportDesc(pItImportDesc, pLibName);
          pItImportDesc++;
        }
      }
    };
  }
}