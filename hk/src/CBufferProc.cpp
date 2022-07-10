#include "pch.h"
#include "CFileProc.h"
#include "CBufferProc.h"
#include "mainFuncs.h"

CBufferProc::CBufferProc(CFileProc* pFP) noexcept
    : m_pFP(pFP),
      m_pBuffer(m_pFP->getBuffer()),
      m_bufferSize(m_pFP->getBufferSize()),
      m_type(m_pFP->getBufferType()) {
  //
}

void CBufferProc::attach(CFileProc* pFP) noexcept {
  m_pFP = pFP;
  m_pBuffer = m_pFP->getBuffer();
  m_bufferSize = m_pFP->getBufferSize();
  m_type = m_pFP->getBufferType();
}

void CBufferProc::attach(DWORD procID) noexcept {
  
  //HANDLE hProc = CreateToolhelp32Snapshot(TH32CS_SNAPALL, procID);
  HANDLE hProc = nullptr;
  HMODULE lphModule = { nullptr };
  DWORD cbRequired = 0;
  wchar_t modulePath[MAX_PATH] = {0};

  printf("Accessing process with PID %d...\t", procID);

  
  if (!(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID))) {
    printf("Failure.\n");
    ERRCHK;
  }

  //BOOL result = DebugActiveProcess(procID);

  printf("Success.\n");

  if (!(EnumProcessModulesEx(hProc, &lphModule, sizeof(lphModule),
                             &cbRequired, LIST_MODULES_ALL))) {
    ERRCHK;
  }

  if (!(GetModuleFileNameEx(hProc, lphModule, modulePath, MAX_PATH))) {
    ERRCHK;
  }

  printf("Retrieved path to process: '%ls'\n", modulePath);

  m_bufferName = modulePath;
  m_pBuffer = (PBYTE)lphModule;

  CFileProc fp(modulePath);

  m_pBuffer = fp.getBuffer();

  analyzePE();

  presentResults(this);

  CloseHandle(hProc);

  _getch();
}

void CBufferProc::parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc,
                                  std::string libName) noexcept {
  if (pImportDesc && libName != "") {
    PIMAGE_NT_HEADERS pNTHdr = peData.pNTHdr;
    PBYTE pBaseAddr = (PBYTE)peData.pDOSHdr;
    std::vector<std::string> collectedFuncs;

    // import lookup table ptrs
    PIMAGE_THUNK_DATA pThunkILT = nullptr;
    PIMAGE_IMPORT_BY_NAME pIBName = nullptr;

    pThunkILT =
        (PIMAGE_THUNK_DATA)((PBYTE)pBaseAddr +
                            util::RVAToOffset(pNTHdr,
                                              pImportDesc->OriginalFirstThunk));

    while (pThunkILT->u1.AddressOfData != 0) {
      // check if function is imported by name and not ordinal
      if (!(pThunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
        pIBName =
            (PIMAGE_IMPORT_BY_NAME)((PBYTE)pBaseAddr +
                                    util::RVAToOffset(
                                        pNTHdr, pThunkILT->u1.AddressOfData));
        collectedFuncs.emplace_back(pIBName->Name);
      } else if (IMAGE_ORDINAL(pThunkILT->u1.Ordinal)) {
        std::ostringstream sstr;
        sstr << "<Ordinal> " << (pThunkILT->u1.Function & 0xffff);
        collectedFuncs.emplace_back(sstr.str());
      }
      pThunkILT++;
    }

    if (!collectedFuncs.empty()) {
      if (m_foundFuncs.try_emplace(libName).second) {
        m_foundFuncs.at(libName) = std::move(collectedFuncs);
      }
    }
  }
}

void CBufferProc::analyzePE() noexcept {
  peData.pDOSHdr = (PIMAGE_DOS_HEADER)m_pBuffer;

  // "MZ" test for little endian x86 CPUs
  if (peData.pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE) {

    // get memory offset to IMAGE_NT_HEADERS
    peData.pNTHdr = PIMAGE_NT_HEADERS((PBYTE)peData.pDOSHdr + peData.pDOSHdr->e_lfanew);

    // "PE" test for little endian x86 CPUs / optional 14th bit (is it EXE or DLL?) test
    if (peData.pNTHdr->Signature == IMAGE_NT_SIGNATURE &&
        !(peData.pNTHdr->FileHeader.Characteristics & (1 << 14))) {
      // get pointer to "optional" header
      peData.pOptHdr = &peData.pNTHdr->OptionalHeader;

      // get import data directory
      PIMAGE_DATA_DIRECTORY pDataDir =
          &peData.pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

      if (pDataDir->Size > 0) {
        peData.pImportDesc = PIMAGE_IMPORT_DESCRIPTOR(
            (PBYTE)peData.pDOSHdr +
            util::RVAToOffset(peData.pNTHdr, pDataDir->VirtualAddress));

        // copy for iteration
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = peData.pImportDesc;

        // step through descriptors and get libraries until there are none
        // left
        while (pImportDesc->Characteristics != NULL) {
        LPSTR pLibName =
            (PCHAR)peData.pDOSHdr +
            util::RVAToOffset(peData.pNTHdr, pImportDesc->Name);
        m_usedLibs.emplace_back(pLibName);
        parseImportDesc(pImportDesc, pLibName);
        pImportDesc++;
        }
      } else {
        LOG("WARNING: import table does not exist in the executable file.");
      }

    pDataDir = &peData.pNTHdr->OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

    if (pDataDir->Size > 0) {
        peData.pResDir = PIMAGE_RESOURCE_DIRECTORY(
            (PBYTE)peData.pDOSHdr +
            util::RVAToOffset(peData.pNTHdr, pDataDir->VirtualAddress));

        return;
    }
    };
  }

  LOG("WARNING: correct header data not found. Buffer is not of an executable type?");
  return;
}

CFileProc* CBufferProc::getSource() noexcept { return m_pFP; }

const std::vector<std::string>& CBufferProc::libs() noexcept {
  return m_usedLibs;
}

const std::map<std::string, std::vector<std::string>>& CBufferProc::funcs() noexcept {
  return m_foundFuncs;
}