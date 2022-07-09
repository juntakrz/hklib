#include "pch.h"
#include "dllfunc.h"

LPVOID getIATEntry(std::string libName, std::string funcName) noexcept {
  if (libName == "" || funcName == "") {
    return nullptr;
  }

  dataLocal.pDOSHdr = (PIMAGE_DOS_HEADER)dataLocal.pBaseAddr;

  if (dataLocal.pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE) {
    dataLocal.pNTHdr = PIMAGE_NT_HEADERS((PBYTE)dataLocal.pDOSHdr +
                                         dataLocal.pDOSHdr->e_lfanew);

    if (dataLocal.pNTHdr->Signature == IMAGE_NT_SIGNATURE) {
      dataLocal.pOptHdr = &dataLocal.pNTHdr->OptionalHeader;

      PIMAGE_DATA_DIRECTORY pDataDir =
          &dataLocal.pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

      if (pDataDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pBaseImportDesc = PIMAGE_IMPORT_DESCRIPTOR(
            (PBYTE)dataLocal.pBaseAddr + pDataDir->VirtualAddress);

        PIMAGE_IMPORT_DESCRIPTOR pItImportDesc = pBaseImportDesc;
        LPSTR pLibName;

        while (pItImportDesc->Characteristics != NULL) {
          if ((pLibName = (PCHAR)dataLocal.pDOSHdr + pItImportDesc->Name) ==
              libName) {
            PIMAGE_THUNK_DATA pThunkILT = nullptr;
            PIMAGE_THUNK_DATA pThunkIAT = nullptr;
            std::string strQuery = "";

            pThunkILT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHdr +
                                          pItImportDesc->OriginalFirstThunk);
            pThunkIAT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHdr +
                                          pItImportDesc->FirstThunk);

            while (pThunkILT->u1.AddressOfData != 0) {
              if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                strQuery = PIMAGE_IMPORT_BY_NAME((PBYTE)dataLocal.pDOSHdr +
                                                 pThunkILT->u1.AddressOfData)
                               ->Name;
                if (strQuery == funcName) {
                  return pThunkIAT;
                }

              } else if (IMAGE_ORDINAL(pThunkILT->u1.Ordinal)) {
                strQuery = std::to_string(pThunkILT->u1.Function & 0xffff);
                if (strQuery == funcName) {
                  return pThunkIAT;
                }
              }
              pThunkILT++;
              pThunkIAT++;
            }
          }
          pItImportDesc++;
        }
      }
    }
  }

  return nullptr;
}

void replaceIATEntry(LPVOID source, LPVOID target) noexcept {
  if (source) {
    DWORD newProtect = 0;
    DWORD oldProtect = 0;
    uint64_t* pSource = (uint64_t*)source;
    uint64_t pTarget = (uint64_t)target;
    VirtualProtect(source, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
    *pSource = pTarget;
    VirtualProtect(source, sizeof(LPVOID), oldProtect, &newProtect);
  }
}

void hijack() noexcept {
  MessageBoxA(0, "This function is hijacked.", "Hi", 0);
}