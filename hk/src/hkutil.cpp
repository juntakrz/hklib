#include "pch.h"
#include "define.h"
#include "hkutil.h"

BYTE hk_util::shellCode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
      "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
      "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
      "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
      "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
      "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
      "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
      "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
      "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
      "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
      "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
      "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
      "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
      "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
      "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
      "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
      "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
      "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
      "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
      "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
      "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
      "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
      "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
      "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
      "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
      "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
      "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
      "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
    "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

size_t hk_util::shellCodeSize = sizeof(hk_util::shellCode);

std::string hk_util::fullPath(const char* relativePath) noexcept {
  char buffer[MAX_PATH] = {};
  GetFullPathNameA(relativePath, MAX_PATH, buffer, nullptr);
  return buffer;
}

std::wstring hk_util::fullPath(const wchar_t* relativePath) noexcept {
  wchar_t wbuffer[MAX_PATH] = {};
  GetFullPathNameW(relativePath, MAX_PATH, wbuffer, nullptr);
  return wbuffer;
}

FARPROC hk_util::procAddr(LPCSTR lpModuleName, LPCSTR lpProcName) noexcept {
  return GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
}

DWORD hk_util::setLocalPrivilege(LPCSTR lpszPrivilege, bool enable) noexcept {
  HANDLE hToken = NULL;
  LUID luidPriv{};
  TOKEN_PRIVILEGES tokenNewState{};
  DWORD privStatus = (enable) ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

  auto fError = [&]() {
    CloseHandle(hToken);
    return GetLastError();
  };

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
    return fError();
  }

  if (!LookupPrivilegeValueA(NULL, lpszPrivilege, &luidPriv)) {
    return fError();
  };

  tokenNewState.PrivilegeCount = 1;
  tokenNewState.Privileges[0].Luid = luidPriv;
  tokenNewState.Privileges[0].Attributes = privStatus;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tokenNewState, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) || GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    return fError();
  }

  CloseHandle(hToken);
  return 0;  // SUCCESS
}

void hk_util::processLogMessage(bool newLine, char level, const wchar_t* logMessage, ...) noexcept {
  const size_t bufferSize = 256u;
  wchar_t buffer[bufferSize];
  va_list args;

  va_start(args, logMessage);
  vswprintf_s(buffer, bufferSize, logMessage, args);
  va_end(args);

  switch (level) {
    case logOK: {
      wprintf(buffer);
      break;
    }
    case logWarning: {
      wprintf(TEXT("\x1b[33mWarning: \x1b[0m\x1b[1m%ls\x1b[0m"), buffer);
      break;
    }
    case logError: {
      wprintf(TEXT("\x1b[31mERROR: \x1b[0m\x1b[1m%ls\x1b[0m"), buffer);
      break;
    }
  }

  if (newLine) {
    std::wcout << TEXT("\n");
  }
}

void hk_util::toWString(LPCSTR inString, std::wstring& outWString) {
  const int32_t bufferSize = MultiByteToWideChar(CP_ACP, 0, inString, -1, NULL, 0);
  outWString.resize(bufferSize);
  MultiByteToWideChar(CP_ACP, 0, inString, -1, &outWString[0], bufferSize);
}

bool hk_util::deserializeImportedFunctionName(const std::string& inSerializedFunctionName, std::string& outFunctionName, uint64_t& outAddress) {
  if (inSerializedFunctionName.empty()) {
    return false;
  }

  const size_t delimiterLocation = inSerializedFunctionName.find_first_of(SERIALIZED_DELIMITER);

  if (delimiterLocation == std::string::npos) {
    outFunctionName = inSerializedFunctionName;
    return false;
  }

  outFunctionName = std::string(inSerializedFunctionName.begin(), inSerializedFunctionName.begin() + delimiterLocation);

  const size_t stringSize = inSerializedFunctionName.size();
  
  // 10 bytes are used to serialize address in the import stream, anything not equal to that is invalid data
  // (delimiter + 8 bytes of address (64 bit OS) + 1 bitmask byte
  if (stringSize - delimiterLocation != sizeof(void*) + 2) {
    return false;
  }

  uint64_t addressValue = 0u;
  uint8_t byteMask = 0u;

  memcpy(&addressValue, &inSerializedFunctionName.c_str()[delimiterLocation + 1], sizeof(void*));
  memcpy(&byteMask, &inSerializedFunctionName.c_str()[stringSize - 1], sizeof(uint8_t));

  // Check if any bytes should actually be zero - this was to avoid null-terminated strings when serialized and exported
  if (byteMask != NULL && byteMask != 0xFF) {
    for (uint8_t maskIndex = 0; maskIndex < sizeof(void*); ++maskIndex) {

      // If bitflag is ticked - that means this address byte is actually 0
      bool isOriginalByteZero = byteMask & (1 << maskIndex);

      if (isOriginalByteZero) {
        ((uint8_t*)&addressValue)[maskIndex] = 0;
      }
    }
  }

  outAddress = addressValue;

  return true;
}