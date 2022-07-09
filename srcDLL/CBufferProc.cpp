#include "pch.h"
#include "CFileProc.h"
#include "CBufferProc.h"

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

void CBufferProc::analyzePE() noexcept {
  if (m_type == bufferType::exec) {
    
    /*
    *  IMPORT LOOKUP TABLE RETRIEVAL
    */
    m_pDOSHdr = (PIMAGE_DOS_HEADER)m_pBuffer;

    // "MZ" test for little endian x86 CPUs
    if (m_pDOSHdr->e_magic == IMAGE_DOS_SIGNATURE) {

      // get memory offset to IMAGE_NT_HEADERS
      m_pNTHdr = PIMAGE_NT_HEADERS((PBYTE)m_pDOSHdr + m_pDOSHdr->e_lfanew);

      // "PE" test for little endian x86 CPUs / optional 14th bit (is it EXE or DLL?) test
      if (m_pNTHdr->Signature == IMAGE_NT_SIGNATURE && !(m_pNTHdr->FileHeader.Characteristics & (1 << 14))) {

        // get pointer to "optional" header
        m_pOptHdr = &m_pNTHdr->OptionalHeader;

        // get import data directory
        PIMAGE_DATA_DIRECTORY pDataDir =
            &m_pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (pDataDir->Size > 0) {
          m_pImportDesc = PIMAGE_IMPORT_DESCRIPTOR(
              (PBYTE)m_pDOSHdr +
              util::RVAToOffset(m_pNTHdr,
                                pDataDir->VirtualAddress));

          // copy for iteration
          PIMAGE_IMPORT_DESCRIPTOR pImportDesc = m_pImportDesc;

          // step through descriptors and get libraries until there are none left
          while (pImportDesc->Characteristics != NULL) {
            LPSTR pLibName =
                (PCHAR)m_pDOSHdr + util::RVAToOffset(m_pNTHdr, pImportDesc->Name);
            m_usedLibs.emplace_back(pLibName);
            parseImportDesc(pImportDesc, pLibName);
            pImportDesc++;
          }
        } else {
          LOG("WARNING: import table does not exist in the executable file.");
        }

        /*
         *  DEFAULT ICON GROUP RETRIEVAL
         */
        pDataDir = &m_pNTHdr->OptionalHeader
                        .DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

        if (pDataDir->Size > 0) {
          PIMAGE_RESOURCE_DIRECTORY pResDir = PIMAGE_RESOURCE_DIRECTORY(
              (PBYTE)m_pDOSHdr +
              util::RVAToOffset(m_pNTHdr, pDataDir->VirtualAddress));

          // store pointer to resource dir
          m_pResDir = pResDir;

          DWORD nTotal =
              m_pResDir->NumberOfNamedEntries + m_pResDir->NumberOfIdEntries;

          PBYTE pResBase = (PBYTE)m_pResDir;

          PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry =
              PIMAGE_RESOURCE_DIRECTORY_ENTRY(m_pResDir + 1);
          
          for (uint8_t i = 0; i < nTotal; i++) {
            pResDirEntry = PIMAGE_RESOURCE_DIRECTORY_ENTRY((PBYTE)pResDirEntry + 8);
     
            // name / id 14 = RT_GROUP_ICON
            if (pResDirEntry->Name == 14) {
              pResDir = PIMAGE_RESOURCE_DIRECTORY(
                  pResBase + pResDirEntry->OffsetToDirectory);

              pResDirEntry =
                  PIMAGE_RESOURCE_DIRECTORY_ENTRY((PBYTE)pResDir + 16);
              
              m_defaultIconGroupId = pResDirEntry->Id;
              return;
            }
          }
        }

        return;
      };
    }
  }

  LOG("WARNING: correct header data not found. Buffer is not of an executable type?");
  return;
}

void CBufferProc::injectIcon(CFileProc* pFPIcon,
                             const std::wstring& outputFile) noexcept {
  if (pFPIcon && pFPIcon->getBufferType() == bufferType::icon) {
    PBYTE pIcon = pFPIcon->getBuffer();
    DWORD iconSize = pFPIcon->getBufferSize();
    std::wstring outputPath =
        (outputFile != L"") ? outputFile : m_pFP->getFilePath();

    wLOG(L"\nInjecting icon: " << pFPIcon->getFilePath() << L"\n\t-> into: "
                               << outputPath);

    // create new file if -o commandline argument is used
    if (outputFile != L"") {
      m_pFP->saveFile(outputPath);
    }

    HANDLE hTgtFile = BeginUpdateResourceW(outputPath.c_str(), FALSE);

    ICON_T icon1;

    GROUPICON_T gIcon;
    gIcon.imageCount = 1;
    gIcon.resType = 1;
    gIcon.icons = icon1;

    // force default icon group to have only one icon with id 1
    if (m_defaultIconGroupId) {
      UpdateResourceW(hTgtFile, RT_GROUP_ICON, MAKEINTRESOURCEW(m_defaultIconGroupId),
                      MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), &gIcon,
                      sizeof(GROUPICON_T));

    } else {
      UpdateResourceW(hTgtFile, RT_GROUP_ICON, MAKEINTRESOURCEW(1),
                      MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), &gIcon,
                      sizeof(GROUPICON_T));

      UpdateResourceW(hTgtFile, RT_GROUP_ICON, L"MAINICON",
                      MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), &gIcon,
                      sizeof(GROUPICON_T));
    }
    // inject icon with id 1 using correct data offset
    UpdateResourceW(hTgtFile, RT_ICON, MAKEINTRESOURCEW(1),
                    MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                    pIcon + pFPIcon->getBufferOffset(),
                    iconSize - pFPIcon->getBufferOffset());

    LOG("Applied icon data offset of "
        << pFPIcon->getBufferOffset() << " bytes and injected "
        << iconSize - pFPIcon->getBufferOffset() << " bytes.");

    EndUpdateResourceW(hTgtFile, FALSE);

    return;
  }

  if (pFPIcon) {
 
    wLOG("ERROR: file '" << pFPIcon->getFilePath()
                      << "' doesn't seem to be an icon and won't be injected.");
    if (outputFile != L"") {
      wLOG("Because of this '" << outputFile << "' will not be created.");
    }
  }
}

void CBufferProc::parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImportDesc, std::string libName) noexcept {
  if (pImportDesc && libName != "") {
    PIMAGE_NT_HEADERS pNTHdr = m_pNTHdr;
    PBYTE pBaseAddr = (PBYTE)m_pDOSHdr;
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

CFileProc* CBufferProc::getSource() noexcept { return m_pFP; }

const std::vector<std::string>& CBufferProc::libs() noexcept {
  return m_usedLibs;
}

const std::map<std::string, std::vector<std::string>>& CBufferProc::funcs() noexcept {
  return m_foundFuncs;
}