#pragma once

class CBuffer {
  std::wstring m_filePath = L"";							// path used to load the file into buffer
  std::unique_ptr<BYTE[]> m_buffer;
  DWORD m_bufferSize = 0;

public:
  CBuffer() = default;										// create an empty buffer object
  CBuffer(BYTE* data, DWORD size);							// create buffer using an array of bytes of data
  CBuffer(std::wstring filePath);							// create buffer from file
  ~CBuffer();

  void attach(BYTE* buffer, DWORD size) noexcept;			// pass data to the buffer object via a pointer
  void attach(std::wstring filePath) noexcept;				// load file into the buffer object

  void save(std::wstring filePath = L"") noexcept;			// save buffer to file (will save to the same file if no parameter is provided)

  PBYTE buffer() noexcept;									// access buffer
  DWORD size() noexcept;									// get buffer size in bytes
};