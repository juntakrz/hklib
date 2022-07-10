#include "pch.h"
#include "CFileProc.h"

CFileProc::CFileProc(const std::wstring& path) noexcept {
  CFileProc::openFile(path);
}

CFileProc::~CFileProc() noexcept {
  if (m_pBuffer) {
    m_pBuffer.release();
  }
}

void CFileProc::openFile(const std::wstring& path) noexcept {
  DWORD lastError = 0;
  m_filePath = path;

  m_hFile = CreateFileW(path.c_str(), GENERIC_READ, 0, 0,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

  lastError = GetLastError();

  // check if file exists
  if (lastError = GetLastError() == ERROR_FILE_NOT_FOUND) {
    LOG("ERROR: could not find the file specified.");
    exit(ERROR_FILE_NOT_FOUND);
  }

  // get file size
  m_fileSize = GetFileSize(m_hFile, 0);

  // prepare buffer for writing to
  m_pBuffer = std::make_unique<BYTE[]>(m_fileSize);

  // check if file was read successfully
  if (!ReadFile(m_hFile, m_pBuffer.get(), m_fileSize, &m_bufferSize, 0) &&
      m_bufferSize != m_fileSize) {
    lastError = GetLastError();
    LOG("ERROR: opened but failed to read the file. Error code: " << lastError);
    exit(lastError);
  };

  CloseHandle(m_hFile);

  // basic format checking
  {
    PWORD pSOF = (PWORD)m_pBuffer.get();  // check for MZ
    if (*pSOF == IMAGE_DOS_SIGNATURE) {
      m_type = bufferType::exec;
    } else {
      // check for 00 01 00 00
      PDWORD pIconSOF = (PDWORD)m_pBuffer.get();
      if (*pIconSOF == 0x00010000) {
        m_type = bufferType::icon;

        // detect if it's a PNG-based or standard ICO file and calculate offset
        PBYTE pScan = m_pBuffer.get();
        PDWORD pCheck = nullptr;

        for (DWORD s = 22; s < 255; s++) {
          pScan = (PBYTE)pSOF + s;

          if (*pScan == 0x89) {
            pCheck = (PDWORD)pScan;
            
            // "PNG number", little endian
            if (*pCheck == 0x474E5089) {
              m_offset = s;
              break;
            };
          }

          if (*pScan == 0x28) {
            pCheck = (PDWORD)pScan;

            // "ICO number", little endian
            if (*pCheck == 0x00000028) {
              m_offset = s;
              break;
            }
          }
        }
      }
    }

    if (m_type == bufferType::none) {
      LOG("WARNING: couldn't determine buffer type, doesn't seem to be an executable or an icon.");
    }
  }

  wLOG("Successfuly read '" << m_filePath << ", size: " << m_bufferSize << " bytes.");
}

void CFileProc::saveFile(const std::wstring& path) noexcept {
  
  DWORD bytesOut = 0;

  HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                             0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

  if (!WriteFile(hFile, m_pBuffer.get(), m_bufferSize, &bytesOut, 0)) {
    wLOG("ERROR: couldn't create file using provided path: " << path);
    exit(404);
  };

  CloseHandle(hFile);

  wLOG("Created file '" << path << "', " << bytesOut << " bytes written.");
}

void CFileProc::getBuffer(BYTE* out_pBuffer, DWORD& out_bufferSize) noexcept {
  out_pBuffer = m_pBuffer.get();
  out_bufferSize = m_bufferSize;
}

BYTE* CFileProc::getBuffer() noexcept { return m_pBuffer.get(); }

DWORD CFileProc::getBufferSize() noexcept { return m_bufferSize; }

bufferType CFileProc::getBufferType() noexcept { return m_type; }

DWORD CFileProc::getBufferOffset() noexcept { return m_offset; }

const std::wstring& CFileProc::getFilePath() const noexcept {
  return m_filePath;
}

const float& CFileProc::calcEntropy() noexcept {
  m_entropy = util::calcShannonEntropy(m_pBuffer.get(), m_bufferSize);
  return m_entropy;
}

const float& CFileProc::getEntropy() noexcept {
  return (m_entropy < 0) ? calcEntropy() : m_entropy;
}