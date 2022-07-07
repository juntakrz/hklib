#pragma once

#define LOG(x) std::cout << x << "\n"
#define wLOG(x) std::wcout << x << L"\n"

#define LOG_ERROR() std::cout << "Error code: " << GetLastError() << "\n"

enum bufferType { none = 0, exec, icon };

#pragma pack(push, 2)
struct ICON_T {
  BYTE width = 0;
  BYTE height = 0;
  BYTE colorCount = 0;
  BYTE reserved = 0;
  WORD planes = 1;
  WORD bpp = 0;
  DWORD bytesInRes = 0;
  WORD id = 1;
};

struct GROUPICON_T {
  WORD reserved = 0;
  WORD resType;
  WORD imageCount;
  ICON_T icons;
};
#pragma pack(pop)