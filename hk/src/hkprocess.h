#pragma once

class hkProcess {
 private:
  std::string m_procPath = "";
  std::unique_ptr<BYTE[]> m_pData;
  TPEB64 m_PEB{};
  DWORD m_imageEntryPoint = 0;
  DWORD m_imageSize = 0;
  CONTEXT m_ctx{};

  TCreateProcess hkCreateProcess =
      (TCreateProcess)hk_util::procAddr("ntdll", "NtCreateProcess");
  TQueryInformationProcess hkQueryInformationProcess =
      (TQueryInformationProcess)hk_util::procAddr("ntdll",
                                                  "NtQueryInformationProcess");
  TSetContextThread hkSetContextThread =
      (TSetContextThread)hk_util::procAddr("ntdll", "NtSetContextThread");
  TGetContextThread hkGetContextThread =
      (TGetContextThread)hk_util::procAddr("ntdll", "NtGetContextThread");

  DWORD init() noexcept;						// read, store and process values from process header
 public:

  //PROCESS_INFORMATION clone structure
  HANDLE hProcess = 0;
  HANDLE hThread = 0;
  DWORD dwProcessId = 0;
  DWORD dwThreadId = 0;

  hkProcess(const char* procPath);               // create hkProcess instance using PE file on a disk
  hkProcess(DWORD PID = 0);                      // create hkProcess instance using running process

  NTSTATUS resetContext() noexcept;				// restore thread context

  const DWORD&	imageEntry() const noexcept;	// entry point of a target process image
  const DWORD&	imageSize() const noexcept;		// size of a target process image
};