#include "pch.h"
#include "appf.h"
#include "dataStruct.h"

void dllInject(DWORD PID) noexcept {
  if (!PID) {
    LOG("ERROR: invalid process ID. Either the process is not running or "
        "couldn't be detected.");
    return;
  }

  // init variables
  DWORD idThread = 0;
  SIZE_T bytesWritten = 0;

  // replace globally stored PID if a new one is provided, else use globally
  // stored PID
  (PID) ? global.PID = PID : PID = global.PID;

  global.dllRelativePath = "hklib.dll";
  global.dllFullPath = util::getFullPath(global.dllRelativePath.c_str());
  std::string moduleName = "Kernel32.dll";
  std::string funcName = "LoadLibraryA";

  LOG("Injecting DLL into PID " << global.PID << ".");

  // get LoadLibraryA
  HMODULE hKernel = GetModuleHandleA(moduleName.c_str());
  LPTHREAD_START_ROUTINE LLAddr =
      (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, funcName.c_str());

  // inject LoadLibraryA with dll path parameter
  global.hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
  global.pAllocatedArg =
      VirtualAllocEx(global.hProc, NULL, global.dllFullPath.size(),
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  WriteProcessMemory(global.hProc, global.pAllocatedArg,
                     (LPCVOID)global.dllFullPath.c_str(),
                     global.dllFullPath.size(), &bytesWritten);

  ERRCHK;

  global.hTInject = CreateRemoteThread(global.hProc, NULL, NULL, LLAddr,
                                       global.pAllocatedArg, NULL, &global.TID);

  LOG("'" << global.dllRelativePath << "' injected from '" << global.dllFullPath
          << "'.");

  WaitForSingleObject(global.hTInject, INFINITE);

  global.dllBaseAddr = getDLLBaseAddr();
  global.addFunction("ejectDLL");
  global.updateOffsets();

  LOG("Injected DLL is ready to accept calls.");
}

void dllEject() noexcept {
  if (global.hLocalDLL) {
    FreeLibrary(global.hLocalDLL);
    global.hLocalDLL = nullptr;
  }

  if (global.hProc) {
    dllCall("ejectDLL", NULL_THREAD, NULL_ID);
    CloseHandle(global.hTInject);
    VirtualFreeEx(global.hProc, global.pAllocatedArg, 0, MEM_RELEASE);
    CloseHandle(global.hProc);
  }
}

DWORD dllCall(LPCSTR function, HANDLE& out_hThread, DWORD& out_idThread,
                      DWORD flags, PBYTE pArg, DWORD sizeArg) noexcept {
  LPTHREAD_START_ROUTINE lpTSR = nullptr;
  HANDLE hThread = 0;
  DWORD idThread = 0, threadResult = 0;
  LPVOID lpArgAddr = nullptr;

  LOG("Calling function '" << function << "'.");

  lpTSR =
      LPTHREAD_START_ROUTINE(global.dllBaseAddr + global.offsetOf(function));

  if (pArg && sizeArg) {
    lpArgAddr = VirtualAllocEx(global.hProc, NULL, global.dllFullPath.size(),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    WriteProcessMemory(global.hProc, lpArgAddr, (LPCVOID)pArg, sizeArg, NULL);
  }

  if (lpTSR) {
    hThread = CreateRemoteThread(global.hProc, NULL, NULL, lpTSR, lpArgAddr,
                                 NULL, &idThread);

    if (hThread) {
      if (!(flags & CALL_NO_WAIT)) {
        WaitForSingleObject(hThread, INFINITE);
      }

      if (!(flags & CALL_NO_RETURN)) {
        GetExitCodeThread(hThread, &threadResult);
      }

      if (flags & CALL_NO_CLOSE) {
        if (out_hThread) {
          out_hThread = hThread;
        }

        if (out_hThread) {
          out_idThread = idThread;
        }

      } else {
        CloseHandle(hThread);
      }

      if (lpArgAddr) {
        VirtualFreeEx(global.hProc, lpArgAddr, 0, MEM_RELEASE);
      }

      return threadResult;
    }
  }

  return -1;
}