#include "pch.h"
#include "dllfunc.h"

void createConsole() noexcept {
  if (AllocConsole()) {
    FILE* fDummyCon;
    freopen_s(&fDummyCon, "CONOUT$", "w", stdout);
    freopen_s(&fDummyCon, "CONIN$", "w", stdin);
    freopen_s(&fDummyCon, "CONOUT$", "w", stderr);
    std::cout.clear();
    std::cin.clear();
    std::cerr.clear();
    std::clog.clear();
  }
}

void outputPEDataToConsole() noexcept {
  std::stringstream sstr;
  sstr << "Base address: 0x" << dataLocal.pBaseAddress << "\n\n";
  for (const auto& it_lib : dataImport.modules) {
    sstr << it_lib << ":\n";
    for (const auto& it_func : dataImport.functions.at(it_lib)) {
      sstr << "\t" << it_func << "\n";
    }
    sstr << "\n";
  }

  std::cout << sstr.str();
}

bool serializeAnalysisDataToMemory() {
  // Calculate data size
  dataImport.dwDataSize = 0;

  for (const auto& it_module : dataImport.modules) {
    dataImport.dwDataSize += (DWORD)it_module.size() + 1;

    if (!it_module.empty()) {
      dataImport.dwDataSize++;  // Add one byte for the delimiter
      for (const auto& it_function : dataImport.functions.at(it_module)) {
        dataImport.dwDataSize += (DWORD)it_function.size() + 1;
      }
      dataImport.dwDataSize++;  // Add one byte for the delimiter
    }
  }

  if (dataImport.dwDataSize == 0) {
    return false;
  }

  dataLocal.hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, dataImport.dwDataSize, dataImport.szShareName);

  if (!dataLocal.hSharedMemory) {
    return false;
  }

  LPVOID lpSharedMemory = MapViewOfFile(dataLocal.hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, dataImport.dwDataSize);

  // Generate data buffer
  PBYTE lpCurrent = (PBYTE)lpSharedMemory;

  for (const auto& it_module : dataImport.modules) {
    memcpy(lpCurrent, it_module.c_str(), it_module.size() + 1);
    lpCurrent += it_module.size() + 1;

    if (dataImport.functions.at(it_module).size()) {
      // Add delimiter (0x1F)
      *lpCurrent = dataImport.delimiter;
      lpCurrent++;

      for (const auto& it_func : dataImport.functions.at(it_module)) {
        memcpy(lpCurrent, it_func.c_str(), it_func.size() + 1);
        lpCurrent += it_func.size() + 1;
      }

      *lpCurrent = dataImport.delimiter;
      lpCurrent++;
    }
  }

  UnmapViewOfFile(lpSharedMemory);

  return true;
}

std::string serializeAddressToString(PBYTE pAddress) {
  std::stringstream sstr;
  BYTE zeroByteFlags = 0u;

  for (uint8_t byteIndex = 0; byteIndex < sizeof(void*); ++byteIndex) {
    BYTE value = pAddress[byteIndex];
    
    if (value == 0u) {
      ++value;
      zeroByteFlags |= 1 << byteIndex;
    }

    sstr << value;
  }

  // Set all bits to 1 to avoid having a null terminated string
  // During deserialization this mask will be ignored if at least one byte is > 1
  if (zeroByteFlags == 0u) {
    zeroByteFlags = 0xFF;
  }

  sstr << zeroByteFlags;

  return sstr.str();
}

std::string serializeOffsetToString(uint64_t offset) {
  std::stringstream sstr;
  PBYTE pOffset = (PBYTE)&offset;
  BYTE zeroByteFlags = 0u;

  for (uint8_t byteIndex = 0; byteIndex < sizeof(void*); ++byteIndex) {
    BYTE value = pOffset[byteIndex];

    if (value == 0u) {
      value = 1;
      zeroByteFlags |= 1 << byteIndex;
    }

    sstr << value;
  }

  // Set all bits to 1 to avoid having a null terminated string
  // During deserialization this mask will be ignored if at least one byte is > 1
  if (zeroByteFlags == 0u) {
    zeroByteFlags = 0xFF;
  }

  sstr << zeroByteFlags;

  return sstr.str();
}
