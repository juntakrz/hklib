#include "../pch.h"
#include "../define.h"
#include "../hkutil.h"
#include "CBuffer.h"

CoreBuffer::CoreBuffer(BYTE* buffer, DWORD size) { attach(buffer, size); }

CoreBuffer::CoreBuffer(std::wstring filePath) { attach(filePath); }

CoreBuffer::~CoreBuffer() {
  if (m_buffer) {
    m_buffer.release();
  }
}

void CoreBuffer::attach(BYTE* pData, DWORD size) noexcept {
  LOGn(logOK, "Creating buffer from data at 0x%x, %d bytes...", pData, size);

  if (m_buffer) {
    m_buffer.release();
  }

  m_buffer = std::make_unique<BYTE[]>(size);
  memcpy(m_buffer.get(), pData, size);

  LOGn(logOK, "\t\tSuccess.");
}

void CoreBuffer::attach(std::wstring filePath) noexcept {
  LOGn(logOK, "Creating buffer from file at '%s', ", filePath);

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

  LOGn(logOK, "%d bytes...", fileSize);

  if (!hFile || fileSize) {
    LOG(logOK, "\t\tFailure.");
    ERRCHK;
  }

  m_buffer = std::make_unique<BYTE[]>(fileSize);

  if (!(ReadFile(hFile, m_buffer.get(), fileSize, &m_bufferSize, NULL)) ||
      (m_bufferSize != fileSize)) {
    LOG(logOK, "\t\tFailure.");
    ERRCHK;
  };

  m_filePath = filePath;
  CloseHandle(hFile);

  LOG(logOK, "\t\tSuccess.");
}

void CoreBuffer::save(std::wstring filePath) noexcept {
  
  DWORD fileSize = 0;
  std::wstring writePath = (!filePath.empty()) ? filePath : m_filePath;
  HANDLE hFile = CreateFileW(writePath.c_str(), GENERIC_WRITE, NULL, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  LOGn(logOK, "Writing buffer to '%ls'...", writePath);

  if (!hFile) {
    LOG(logOK, "\t\t\tFailure.");
    ERRCHK;
  }

  if (!(WriteFile(hFile, m_buffer.get(), m_bufferSize, &fileSize, NULL)) ||
      (fileSize != m_bufferSize)) {
    LOG(logOK, "\t\t\tFailure.");
    ERRCHK;
  };

  CloseHandle(hFile);

  LOG(logOK, "\t\t\tSuccess. %d bytes written.", fileSize);
}

PBYTE CoreBuffer::buffer() noexcept { return m_buffer.get(); }

DWORD CoreBuffer::size() noexcept { return m_bufferSize; }
