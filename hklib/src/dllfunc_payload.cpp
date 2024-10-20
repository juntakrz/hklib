#include "pch.h"
#include "dllfunc.h"

LPVOID getIATEntry(const std::string& libraryName, const std::string& functionName) noexcept {
  if (libraryName == "" || functionName == "") {
    return nullptr;
  }

  dataLocal.pDOSHeader = (PIMAGE_DOS_HEADER)dataLocal.pBaseAddress;

  if (dataLocal.pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return nullptr;
  }

  dataLocal.pNTHeader = PIMAGE_NT_HEADERS((PBYTE)dataLocal.pDOSHeader + dataLocal.pDOSHeader->e_lfanew);

  if (dataLocal.pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
    return nullptr;
  }

  dataLocal.pOptionalHeader = &dataLocal.pNTHeader->OptionalHeader;

  PIMAGE_DATA_DIRECTORY pDataDirectory = &dataLocal.pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (pDataDirectory->Size == 0) {
    return nullptr;
  }

  PIMAGE_IMPORT_DESCRIPTOR pBaseImportDesc = PIMAGE_IMPORT_DESCRIPTOR((PBYTE)dataLocal.pBaseAddress + pDataDirectory->VirtualAddress);
  PIMAGE_IMPORT_DESCRIPTOR pItImportDesc = pBaseImportDesc;
  LPSTR pLibName;

  while (pItImportDesc->Characteristics != NULL) {

    if ((pLibName = (PCHAR)dataLocal.pDOSHeader + pItImportDesc->Name) == libraryName) {
      PIMAGE_THUNK_DATA pThunkILT = nullptr;
      PIMAGE_THUNK_DATA pThunkIAT = nullptr;
      std::string strQuery = "";

      pThunkILT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHeader + pItImportDesc->OriginalFirstThunk);
      pThunkIAT = PIMAGE_THUNK_DATA((PBYTE)dataLocal.pDOSHeader + pItImportDesc->FirstThunk);

      while (pThunkILT->u1.AddressOfData != 0) {

        if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {

          strQuery = PIMAGE_IMPORT_BY_NAME((PBYTE)dataLocal.pDOSHeader + pThunkILT->u1.AddressOfData)->Name;

          if (strQuery == functionName) {
            return pThunkIAT;
          }

        } else if (IMAGE_ORDINAL(pThunkILT->u1.Ordinal)) {
          strQuery = std::to_string(pThunkILT->u1.Function & 0xffff);

          if (strQuery == functionName) {
            return pThunkIAT;
          }
        }

        pThunkILT++;
        pThunkIAT++;
      }
    }

    pItImportDesc++;
  }

  return nullptr;
}

void replaceIATEntry(LPVOID lpSource, LPVOID lpTarget) noexcept {
  if (!lpSource) {
    return;
  }

  DWORD newProtect = 0;
  DWORD oldProtect = 0;
  uint64_t* pSource = (uint64_t*)lpSource;
  uint64_t pTarget = (uint64_t)lpTarget;
  VirtualProtect(lpSource, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);
  *pSource = pTarget;
  VirtualProtect(lpSource, sizeof(LPVOID), oldProtect, &newProtect);
}

void hijack() noexcept {
  MessageBoxA(0, "This function is hijacked.", "Hi", 0);
}