#pragma once

namespace hk_pe {
struct {
  PIMAGE_DOS_HEADER pDOSHdr = nullptr;								        // base address of PE image
  PIMAGE_NT_HEADERS pNTHdr = nullptr;
  PIMAGE_SECTION_HEADER pSecHdr = nullptr;                                  // first section header
  PIMAGE_EXPORT_DIRECTORY pExportDir = nullptr;
  PIMAGE_DATA_DIRECTORY pImportDir = nullptr;

  bool isDLL = false;
} PEData;

bool readPEHeaderData(BYTE* buffer) noexcept;					            // reads data from PE header
bool readPEExportData(BYTE* buffer) noexcept;                               // reads data from PE export directory
bool readPEImportData(BYTE* buffer) noexcept;	                            // reads data from PE import directory
bool getPEFunctionOffsetAndSize(const char* in_function, DWORD* out_size,   // gets an offset to function and its size in the PE image
                                DWORD* out_offset) noexcept;
}