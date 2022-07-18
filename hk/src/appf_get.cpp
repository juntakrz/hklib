#include "pch.h"
#include "dataStruct.h"
#include "appf.h"

DWORD getProcessID(const wchar_t* process) noexcept {
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(PROCESSENTRY32W);

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (!(hSnapshot == INVALID_HANDLE_VALUE)) {
    do {
      if (wcscmp(process, pe.szExeFile) == 0) {
        global.PID = pe.th32ProcessID;
        if (!CloseHandle(hSnapshot)) {
          ERRCHK;
        };
        return global.PID;
      }
    } while (Process32NextW(hSnapshot, &pe));
  }

  return 0;
}