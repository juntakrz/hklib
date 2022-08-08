#include "../pch.h"
#include "../define.h"
#include "CBuffer.h"

CBuffer::CBuffer(BYTE* buffer, DWORD size) { attach(buffer, size); }

CBuffer::CBuffer(std::wstring filePath) { attach(filePath); }

CBuffer::~CBuffer() {
  if (m_buffer) {
    m_buffer.release();
  }
}

void CBuffer::attach(BYTE* data, DWORD size) noexcept {
  LOGn("Creating buffer from data at " << data << ", " << size << " bytes...");

  if (m_buffer) {
    m_buffer.release();
  }

  m_buffer = std::make_unique<BYTE[]>(size);
  memcpy(m_buffer.get(), data, size);

  LOGn("\t\tSuccess.");
}

void CBuffer::attach(std::wstring filePath) noexcept {
  wLOGn("Creating buffer from file at '" << filePath << "', ");

  HANDLE hFile = nullptr;
  DWORD fileSize = 0;

  if (m_buffer) {
    m_buffer.release();
  }

  hFile = CreateFileW(filePath.c_str(), GENERIC_READ, NULL, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile) {
    fileSize = GetFileSize(hFile, NULL);
  }

  LOGn(fileSize << " bytes...");

  if (!hFile || fileSize) {
    LOG("\t\tFailure.");
    ERRCHK;
  }

  m_buffer = std::make_unique<BYTE[]>(fileSize);

  if (!(ReadFile(hFile, m_buffer.get(), fileSize, &m_bufferSize, NULL)) ||
      (m_bufferSize != fileSize)) {
    LOG("\t\tFailure.");
    ERRCHK;
  };

  m_filePath = filePath;
  CloseHandle(hFile);

  LOG("\t\tSuccess.");
}

void CBuffer::save(std::wstring filePath) noexcept {
  
  DWORD fileSize = 0;
  std::wstring writePath = (!filePath.empty()) ? filePath : m_filePath;
  HANDLE hFile = CreateFileW(writePath.c_str(), GENERIC_WRITE, NULL, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  wLOGn("Writing buffer to '" << writePath << "'...");

  if (!hFile) {
    LOG("\t\t\tFailure.");
    ERRCHK;
  }

  if (!(WriteFile(hFile, m_buffer.get(), m_bufferSize, &fileSize, NULL)) ||
      (fileSize != m_bufferSize)) {
    LOG("\t\t\tFailure.");
    ERRCHK;
  };

  CloseHandle(hFile);

  LOG("\t\t\tSuccess. " << fileSize << " bytes written.");
}

PBYTE CBuffer::buffer() noexcept { return m_buffer.get(); }

DWORD CBuffer::size() noexcept { return m_bufferSize; }
