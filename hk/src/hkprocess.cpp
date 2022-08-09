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

  pData = std::make_unique<BYTE[]>(bufSize);
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
                         &hkPEB64, sizeof(hkPEB64), nullptr)) {
    LOG("ERROR: Failed to read process environment block.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  // process image starts at an offset of +16 bytes (+0x10) from PEB base
  // address, at 'Reserved3[1]'
  if (!ReadProcessMemory(hProcess, hkPEB64.ImageBaseAddress, pData.get(),
                         bufSize, &bytesRead) ||
      bytesRead != bufSize) {
    LOG("ERROR: Failed to read target image header from address 0x"
        << std::hex << hkPEB64.ImageBaseAddress << " in PEB.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  WORD e_magic = *(PWORD)pData.get();

  if (*(PWORD)pData.get() != IMAGE_DOS_SIGNATURE) {
    LOG("ERROR: Incorrect image DOS header. Valid signature not found.");
    TerminateProcess(hProcess, 0);
    return IMAGE_DOS_SIGNATURE;
  }

  PIMAGE_DOS_HEADER pHdrDOS = (PIMAGE_DOS_HEADER)pData.get();
  PIMAGE_NT_HEADERS64 pHdrNT =
      PIMAGE_NT_HEADERS64((PBYTE)pHdrDOS + pHdrDOS->e_lfanew);

  if (pHdrNT->Signature != IMAGE_NT_SIGNATURE) {
    LOG("ERROR: Incorrect image NT header. Valid signature not found.");
    TerminateProcess(hProcess, 0);
    return IMAGE_NT_SIGNATURE;
  }

  imageEntryPoint = pHdrNT->OptionalHeader.AddressOfEntryPoint;
  imageSize = pHdrNT->OptionalHeader.SizeOfImage;

  // store whole process image for further analysis / manipulation
  pData.release();
  pData = std::make_unique<BYTE[]>(imageSize);

  if (!ReadProcessMemory(hProcess, hkPEB64.ImageBaseAddress, pData.get(),
                         imageSize, &bytesRead) ||
      bytesRead != imageSize) {
    LOG("ERROR: Failed to read and store whole image.");
    TerminateProcess(hProcess, 0);
    return GetLastError();
  }

  return 0;
}