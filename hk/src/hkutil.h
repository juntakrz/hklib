#pragma once

namespace hk_util {

extern BYTE shellCode[];
extern size_t shellCodeSize;

template <typename T>
bool checkFlag(T flags, uint8_t pos) noexcept {
  return flags & (1 << pos);
}

template <typename T>
T RVAToOffset(PIMAGE_NT_HEADERS pNTHeader, T RVA) noexcept {
  PIMAGE_SECTION_HEADER pSecHdr = IMAGE_FIRST_SECTION(pNTHeader);
  WORD numSections = pNTHeader->FileHeader.NumberOfSections;

  if (RVA == 0) {
    return RVA;
  }

  for (WORD i = 0; i < numSections; i++) {
    if (pSecHdr->VirtualAddress <= RVA &&
        (pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize) > RVA) {
      break;
    }
    pSecHdr++;
  }
  return RVA - pSecHdr->VirtualAddress + pSecHdr->PointerToRawData;
}

template <typename T>
float calcShannonEntropy(PBYTE pBuffer, T bufferSize) noexcept {
  // e = E(0-255) -p*log2(p)
  float sigma = 0.0f;
  float p = 0.0f;
  uint32_t pData[256] = {0};

  for (T i = 0; i < bufferSize; i++) {
    pData[*pBuffer]++;
    pBuffer++;
  }

  for (uint16_t j = 0; j < 256; j++) {
    p = (float)pData[j] / bufferSize;

    if (p > 0) {
      sigma += -p * log2f(p);
    }
  }

  return sigma;
}

// file system
std::string fullPath(const char* relativePath) noexcept;
std::wstring fullPath(const wchar_t* relativePath) noexcept;

// general
FARPROC procAddr(LPCSTR lpModuleName, LPCSTR lpProcName) noexcept;
DWORD setLocalPrivilege(LPCSTR lpszPrivilege, bool enable = true) noexcept;

void processLogMessage(bool newLine, char level, const wchar_t* logMessage, ...) noexcept;
void toWString(LPCSTR inString, std::wstring& outWString);

bool deserializeImportedFunctionName(const std::string& inSerializedFunctionName, std::string& outFunctionName, uint64_t& outAddress);

}  // namespace util