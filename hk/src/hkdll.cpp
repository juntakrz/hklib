#include "pch.h"
#include "define.h"
#include "hkdll.h"
#include "datastruct.h"
#include "hkutil.h"

void hk_dll::inject(DWORD PID) noexcept {
  if (!PID) {
    LOG(logError, "Invalid process ID. Either the process is not running or couldn't be detected.");
    return;
  }

  // init variables
  DWORD idThread = 0;
  SIZE_T bytesWritten = 0;

  // replace globally stored PID if a new one is provided, else use globally
  // stored PID
  (PID) ? global.PID = PID : PID = global.PID;

  global.dllRelativePath = TEXT("hklib.dll");
  global.dllFullPath = hk_util::fullPath(global.dllRelativePath.c_str());
  std::string moduleName = "Kernel32.dll";
  std::string funcName = "LoadLibraryA";

  LOG(logOK, "Injecting DLL into PID %d.", global.PID);

  // get LoadLibraryA
  HMODULE hKernel = GetModuleHandleA(moduleName.c_str());
  LPTHREAD_START_ROUTINE LLAddr =
      (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, funcName.c_str());

  // inject LoadLibraryA with dll path parameter
  std::string dllFullPathA;
  std::transform(global.dllFullPath.begin(), global.dllFullPath.end(), std::back_inserter(dllFullPathA), [](wchar_t c) {
    return (char)c;
    }
  );

  LOG(logOK, "Injecting '%ls' from '%ls'.", global.dllRelativePath.c_str(), global.dllFullPath.c_str());

  global.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
  global.pAllocatedAddress = VirtualAllocEx(global.hProcess, NULL, dllFullPathA.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  WriteProcessMemory(global.hProcess, global.pAllocatedAddress, (LPCVOID)dllFullPathA.c_str(), dllFullPathA.size(), &bytesWritten);

  ERRCHK;

  global.hTInject = CreateRemoteThread(global.hProcess, NULL, NULL, LLAddr,global.pAllocatedAddress, NULL, &global.TID);

  WaitForSingleObject(global.hTInject, INFINITE);

  global.dllBaseAddr = hk_dll::getBaseAddr();

  if (global.dllBaseAddr == -1) {
    LOG(logError, "DLL injection failed.");
    exit(404);
  }

  global.addFunction("ejectDLL");
  global.updateOffsets();

  LOG(logOK, "Injected DLL is ready to accept calls.");
}

void hk_dll::eject() noexcept {
  if (global.hLocalDLL) {
    FreeLibrary(global.hLocalDLL);
    global.hLocalDLL = nullptr;
  }

  if (global.hProcess) {
    hk_dll::call("ejectDLL", NULL_THREAD, NULL_ID);
    CloseHandle(global.hTInject);
    VirtualFreeEx(global.hProcess, global.pAllocatedAddress, 0, MEM_RELEASE);
    CloseHandle(global.hProcess);
  }
}

DWORD hk_dll::call(LPCSTR function, HANDLE& outHThread, DWORD& outIdThread, DWORD flags, PBYTE pArg, DWORD sizeArg) noexcept {
  LPTHREAD_START_ROUTINE lpTSR = nullptr;
  HANDLE hThread = 0;
  DWORD idThread = 0, threadResult = 0;
  LPVOID lpArgAddress = nullptr;

  std::wstring wideFunctionName;
  hk_util::toWString(function, wideFunctionName);

  LOG(logOK, "Calling function '%ls'.", wideFunctionName.c_str());

  lpTSR = LPTHREAD_START_ROUTINE(global.dllBaseAddr + global.offsetOf(function));

  if (pArg && sizeArg) {
    lpArgAddress = VirtualAllocEx(global.hProcess, NULL, global.dllFullPath.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(global.hProcess, lpArgAddress, (LPCVOID)pArg, sizeArg, NULL);
  }

  if (lpTSR) {
    hThread = CreateRemoteThread(global.hProcess, NULL, NULL, lpTSR, lpArgAddress, NULL, &idThread);

    if (!hThread) {
      return -1;
    }

    if (!(flags & CALL_NO_WAIT)) {
      WaitForSingleObject(hThread, INFINITE);
    }

    if (!(flags & CALL_NO_RETURN)) {
      GetExitCodeThread(hThread, &threadResult);
    }

    if (flags & CALL_NO_CLOSE) {

      if (outHThread) {
        outHThread = hThread;
        outIdThread = idThread;
      }

    } else {
      CloseHandle(hThread);
    }

    if (lpArgAddress) {
      VirtualFreeEx(global.hProcess, lpArgAddress, 0, MEM_RELEASE);
    }

    return threadResult;
  }

  return -1;
}

uint64_t hk_dll::getBaseAddr() noexcept {
  MODULEENTRY32W moduleEntry{};
  moduleEntry.dwSize = sizeof(MODULEENTRY32W);

  HANDLE hSnapshot = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, global.PID);

  if (hSnapshot == INVALID_HANDLE_VALUE) {
    LOG(logError, "Failed to retrieve base address for the HK dll.");
    return -1;
  }

  do {
    if (moduleEntry.szModule == global.dllName) {

      if (!CloseHandle(hSnapshot)) {
        ERRCHK;
      };

      return (uint64_t)moduleEntry.modBaseAddr;
    }
  } while (Module32NextW(hSnapshot, &moduleEntry));

  LOG(logError, "Failed to retrieve base address for the HK dll.");
  return -1;
}

DWORD hk_dll::getExportOffset(LPCSTR funcName) noexcept {
  if (!global.hLocalDLL) {
    global.hLocalDLL = LoadLibrary(global.dllFullPath.c_str());

    if (!global.hLocalDLL) {
      LOG(logError, "Failed to load '%s'.\n", global.dllFullPath);
      ERRCHK;
    }
  }

  LPVOID funcAddr = GetProcAddress(global.hLocalDLL, funcName);
  if (!funcAddr) {
    LOG(logError, "Failed to locate function '%s'.\n", funcName);
    ERRCHK;
  }

  DWORD offset = DWORD((PBYTE)funcAddr - (PBYTE)global.hLocalDLL);

  return offset;
}