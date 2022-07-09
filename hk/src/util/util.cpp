#include "../pch.h"
#include "util.h"

std::string util::getFullPath(const char* relativePath) noexcept {
  char buffer[MAX_PATH] = {};
  GetFullPathNameA(relativePath, MAX_PATH, buffer, nullptr);
  return buffer;
}

std::wstring util::getFullPath(const wchar_t* relativePath) noexcept {
  wchar_t wbuffer[MAX_PATH] = {};
  GetFullPathNameW(relativePath, MAX_PATH, wbuffer, nullptr);
  return wbuffer;
}
