#include "pch.h"
#include "define.h"
#include "hkdll.h"
#include "datastruct.h"
#include "hkutil.h"

void hk_dll::inject(DWORD PID) noexcept {
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
  global.dllFullPath = hk_util::fullPath(global.dllRelativePath.c_str());
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

  global.dllBaseAddr = hk_dll::getBaseAddr();
  global.addFunction("ejectDLL");
  global.updateOffsets();

  LOG("Injected DLL is ready to accept calls.");
}

void hk_dll::eject() noexcept {
  if (global.hLocalDLL) {
    FreeLibrary(global.hLocalDLL);
    global.hLocalDLL = nullptr;
  }

  if (global.hProc) {
    hk_dll::call("ejectDLL", NULL_THREAD, NULL_ID);
    CloseHandle(global.hTInject);
    VirtualFreeEx(global.hProc, global.pAllocatedArg, 0, MEM_RELEASE);
    CloseHandle(global.hProc);
  }
}

DWORD hk_dll::call(LPCSTR function, HANDLE& out_hThread, DWORD& out_idThread,
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

uint64_t hk_dll::getBaseAddr() noexcept {
  MODULEENTRY32W me{};
  me.dwSize = sizeof(MODULEENTRY32W);

  HANDLE hSnapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, global.PID);

  if (!(hSnapshot == INVALID_HANDLE_VALUE)) {
    do {
      if (me.szModule == global.dllName) {
        global.dllBaseAddr = (uint64_t)me.modBaseAddr;
        if (!CloseHandle(hSnapshot)) {
          ERRCHK;
        };
        return global.dllBaseAddr;
      }
    } while (Module32NextW(hSnapshot, &me));
  }

  return 0;
}

DWORD hk_dll::getExportOffset(LPCSTR funcName) noexcept {
  if (!global.hLocalDLL) {
    global.hLocalDLL = LoadLibraryA(global.dllFullPath.c_str());

    if (!global.hLocalDLL) {
      LOG("ERROR: failed to load '" << global.dllFullPath << "'.\n");
      ERRCHK;
    }
  }

  LPVOID funcAddr = GetProcAddress(global.hLocalDLL, funcName);
  if (!funcAddr) {
    LOG("ERROR: failed to locate function '" << funcName << "'.\n");
    ERRCHK;
  }

  DWORD offset = (PBYTE)funcAddr - (PBYTE)global.hLocalDLL;

  return offset;
}