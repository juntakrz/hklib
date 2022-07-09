#pragma once

class CBufferProc {

  CFileProc* m_pFP = nullptr;
  BYTE* m_pBuffer = nullptr;
  DWORD m_bufferSize = 0;
  bufferType m_type = bufferType::none;
  DWORD m_defaultIconGroupId = 0;

  PIMAGE_DOS_HEADER m_pDOSHdr = nullptr;
  PIMAGE_NT_HEADERS m_pNTHdr = nullptr;
  PIMAGE_OPTIONAL_HEADER m_pOptHdr = nullptr;       // contains ptr to data directories
  PIMAGE_IMPORT_DESCRIPTOR m_pImportDesc = nullptr; // first import descriptor
  PIMAGE_RESOURCE_DIRECTORY m_pResDir = nullptr;    // resource directory root

  std::vector<std::string> m_usedLibs;
  std::map<std::string, std::vector<std::string>> m_foundFuncs;

 private:
  void parseImportDesc(PIMAGE_IMPORT_DESCRIPTOR pImpDesc = nullptr,
                       std::string libName = "") noexcept;

 public:
  CBufferProc(CFileProc* pFP) noexcept;
  ~CBufferProc(){};

  void attach(CFileProc* pFP) noexcept;

  void analyzePE() noexcept;
  void injectIcon(CFileProc* pFPIcon, const std::wstring& outputFile = L"") noexcept;

  CFileProc* getSource() noexcept;
  const std::vector<std::string>& libs() noexcept;
  const std::map<std::string, std::vector<std::string>>& funcs() noexcept;
};