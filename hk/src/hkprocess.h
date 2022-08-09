#pragma once

class hkProcess {
 private:
  std::string m_procPath = "";
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

  TPEB64 hkPEB64{};
  DWORD imageEntryPoint = 0;
  DWORD imageSize = 0;
  std::unique_ptr<BYTE[]> pData;

  hkProcess(const char* procPath);               // create hkProcess instance using PE file on a disk
  hkProcess(DWORD PID = 0);                      // create hkProcess instance using running process

  NTSTATUS resetContext() noexcept;				// restore thread context
};