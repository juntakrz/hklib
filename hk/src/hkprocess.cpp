#include "pch.h"
#include "hkutil.h"
#include "define.h"
#include "hkprocess.h"

hkProcess::hkProcess(const char* procPath) : m_procPath(procPath) {
  DWORD errorCode = 0;      // 0 = no error
  if (!procPath) {
    LOG("ERROR: Path to process '" << m_procPath << "' is incorrect.\nPress ANY key to exit");
    _getch();
    exit(404);
  }

  LOG("Creating target process using '" << m_procPath << "'.");

  if (errorCode = init()) {
    LOG("ERROR: Failed creating target class object. Error code: " << errorCode
                                                                   << ".");
    LOG("Terminating opened process and exiting.\nPress ANY key to exit.");
    _getch();
    TerminateProcess(hProcess, errorCode);
    exit(errorCode);
  };

  LOG("SUCCESS: Target process (PID " << dwProcessId << ") created and is ready for action.\n");
}

NTSTATUS hkProcess::resetContext() noexcept { return hkSetContextThread(hThread, &m_ctx); }

const DWORD& hkProcess::imageEntry() const noexcept { return m_imageEntryPoint; }

const DWORD& hkProcess::imageSize() const noexcept { return m_imageSize; }

DWORD hkProcess::init() noexcept {
  // initialziation
  STARTUPINFOA startupInfo{};
  PROCESS_INFORMATION procInfo{};
  PROCESS_BASIC_INFORMATION procBasicInfo{};

  SIZE_T bufSize =
      4096;  // 4 KB should be enough to read all the required header data
  SIZE_T bytesRead = 0;
  DWORD lastError = 0;
  DWORD64 PEBImageOffset = 0;

  m_pData = std::make_unique<BYTE[]>(bufSize);
  m_ctx.ContextFlags = CONTEXT_FULL;

  if (!CreateProcessA(m_procPath.c_str(), NULL, NULL, NULL, TRUE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                      &startupInfo, &procInfo)) {
    LOG("ERROR: Failed to create process '" << m_procPath << "'.");
    return GetLastError();
  }

  // store process information
  memcpy(&hProcess, &procInfo, sizeof(PROCESS_INFORMATION));

  /*hkCreateProcess(&m_procInfo.hProcess, PROCESS_ALL_ACCESS, NULL,
                  GetCurrentProcess(), TRUE, NULL, NULL, NULL);*/

  if (hkGetContextThread(hThread, &m_ctx)) {
    LOG("ERROR: Failed to get target thread context.");
    return GetLastError();
  };

  if (!OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId)) {
    LOG("ERROR: Failed to open process with ID: "
        << dwProcessId << ". Error code: " << GetLastError());
    TerminateProcess(hProcess, 0);
    return false;
  }

  hkQueryInformationProcess(hProcess, ProcessBasicInformation,
                            &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION),
                            nullptr);

  // read PEB from target process memory and store data in a temporary PEB structure
  if (!ReadProcessMemory(hProcess, procBasicInfo.PebBaseAddress,
                         &m_PEB, sizeof(PEB), nullptr)) {
    LOG("ERROR: Failed to read process environment block.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  // process image starts at an offset of +16 bytes (+0x10) from PEB base
  // address, at 'Reserved3[1]'
  if (!ReadProcessMemory(hProcess, m_PEB.ImageBaseAddress, m_pData.get(),
                         bufSize, &bytesRead) ||
      bytesRead != bufSize) {
    LOG("ERROR: Failed to read target image header from address 0x"
        << std::hex << m_PEB.ImageBaseAddress << " in PEB.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  WORD e_magic = *(PWORD)m_pData.get();

  if (*(PWORD)m_pData.get() != IMAGE_DOS_SIGNATURE) {
    LOG("ERROR: Incorrect image DOS header. Valid signature not found.");
    TerminateProcess(hProcess, 0);
    return IMAGE_DOS_SIGNATURE;
  }

  PIMAGE_DOS_HEADER pHdrDOS = (PIMAGE_DOS_HEADER)m_pData.get();
  PIMAGE_NT_HEADERS64 pHdrNT =
      PIMAGE_NT_HEADERS64((PBYTE)pHdrDOS + pHdrDOS->e_lfanew);

  if (pHdrNT->Signature != IMAGE_NT_SIGNATURE) {
    LOG("ERROR: Incorrect image NT header. Valid signature not found.");
    TerminateProcess(hProcess, 0);
    return IMAGE_NT_SIGNATURE;
  }

  m_imageEntryPoint = pHdrNT->OptionalHeader.AddressOfEntryPoint;
  m_imageSize = pHdrNT->OptionalHeader.SizeOfImage;

  // store whole process image for further analysis / manipulation
  m_pData.release();
  m_pData = std::make_unique<BYTE[]>(m_imageSize);

  if (!ReadProcessMemory(hProcess, m_PEB.ImageBaseAddress, m_pData.get(),
                         m_imageSize, &bytesRead) ||
      bytesRead != m_imageSize) {
    LOG("ERROR: Failed to read and store whole image.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  return 0;
}