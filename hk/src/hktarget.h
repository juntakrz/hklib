#pragma once

class hkTarget {
 private:
  PROCESS_INFORMATION m_procInfo{};
  PROCESS_BASIC_INFORMATION m_procBasicInfo{};
  std::string m_procPath = "";
  std::unique_ptr<BYTE[]> m_pData;
  DWORD m_imageEntryPoint = 0;
  DWORD m_imageSize = 0;

  DWORD init() noexcept;		// read, store and process values from process header
 public:
  hkTarget(const char* procPath);

  const HANDLE&	hProcess() const noexcept;		// handle of a target process
  const DWORD&	dwProcessId() const noexcept;	// id of a target process
  const HANDLE& hThread() const noexcept;		// handle of a target thread
  const DWORD&	dwThreadId() const noexcept;	// id of a target thread
  const DWORD&	imageEntry() const noexcept;	// entry point of a target process image
  const DWORD&	imageSize() const noexcept;		// size of a target process image
};