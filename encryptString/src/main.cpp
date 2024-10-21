#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>

#define FILENAME_IN "strings.txt"
#define FILENAME_OUT "encrypted.bin"
#define LINE_DELIMITER '\r'

std::vector<std::string> sourceStrings;
std::vector<std::string> encryptedStrings;
uint64_t encryptionKey = 0;

void printHelpAndExit() {
  wprintf_s(L"USAGE: place ASCII encoded 'strings.txt' into the same folder as this executable, the first string should be an 8 byte integer which will be used as an encryption key followed by strings that need to be encrypted.\n");
  exit(1);
}

bool stringToUint64(const std::string& inString, uint64_t& outNumber) {
  std::istringstream iss(inString);
  iss >> outNumber;
  return !(iss.fail());
}

void readFile(const std::string& fileName) {
  std::ifstream file(fileName);

  if (!file) {
    printHelpAndExit();
  }

  std::string encryptionKeyString;
  if (!std::getline(file, encryptionKeyString, LINE_DELIMITER)) {
    file.close();
    printHelpAndExit();
  }

  if (!stringToUint64(encryptionKeyString, encryptionKey)) {
    file.close();
    printHelpAndExit();
  }

  std::string currentString = "";
  while (std::getline(file, currentString, LINE_DELIMITER)) {
    sourceStrings.emplace_back(currentString);
  }

  if (sourceStrings.empty()) {
    file.close();
    printHelpAndExit();
  }
}

void encryptStrings() {
  for (const std::string& currentString : sourceStrings) {
    std::string encryptedString = "";
    const size_t stringSize = currentString.size();
    encryptedString.resize(stringSize);

    for (size_t stringPosition = 0; stringPosition < stringSize; ++stringPosition) {
      const uint8_t* pEncryptionKey = (uint8_t*)&encryptionKey;
      const uint8_t encryptionByte = pEncryptionKey[stringPosition % sizeof(uint64_t)];
      encryptedString[stringPosition] = currentString[stringPosition] ^ encryptionByte;
    }

    encryptedStrings.emplace_back(encryptedString);
  }
}

void saveFile(const std::string& fileName) {
  std::ofstream file(FILENAME_OUT, std::ios::binary);

  if (encryptedStrings.empty() || !file) {
    wprintf_s(L"Failed to save the file.\n");
    exit(2);
  }

  for (const std::string& currentString : encryptedStrings) {
    file << currentString << "\xFF\xFF\xF7\xF7\xFF";
  }

  file.close();

  wprintf_s(L"Successfully saved the file.\n");
}

int wmain(int argc, wchar_t* argv[]) {
  readFile(FILENAME_IN);
  encryptStrings();
  saveFile(FILENAME_OUT);

  return 0;
}