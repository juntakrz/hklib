#pragma once

class CBufferProc {

  CFileProc* m_pFP = nullptr;
  PBYTE m_pBuffer = nullptr;
  DWORD m_bufferSize = 0;
  std::wstring m_bufferName = L"";
  bufferType m_type = bufferType::none;
  DWORD m_defaultIconGroupId = 0;

  struct PEData {
    PIMAGE_DOS_HEADER pDOSHdr = nullptr;
    PIMAGE_NT_HEADERS pNTHdr = nullptr;
    PIMAGE_OPTIONAL_HEADER pOptHdr = nullptr;         // contains ptr to data directories
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;   // first import descriptor
    PIMAGE_RESOURCE_DIRECTORY pResDir = nullptr;      // resource directory root
  } peData;

  std::vector<std::string> m_usedLibs;
  std::map<std::string, std::vector<std::string>> m_foundFuncs;

 private:
  void parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImpDesc = nullptr,
                       std::string libName = "") noexcept;

 public:
  CBufferProc(){};
  CBufferProc(CFileProc* pFP) noexcept;
  ~CBufferProc(){};

  void attach(CFileProc* pFP) noexcept;
  void attach(DWORD procID) noexcept;

  void analyzePE() noexcept;

  CFileProc* getSource() noexcept;
  const std::vector<std::string>& libs() noexcept;
  const std::map<std::string, std::vector<std::string>>& funcs() noexcept;
};