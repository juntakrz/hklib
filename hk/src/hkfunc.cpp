#include "pch.h"
#include "hkutil.h"
#include "hkfunc.h"

TAllocateVirtualMemory hkAllocateVirtualMemory = nullptr;
TCreateProcess hkCreateProcess = nullptr;
TCreateSection hkCreateSection = nullptr;
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
  hkAllocateVirtualMemory = (TAllocateVirtualMemory)util::getFunctionAddress("ntdll", "NtAllocateVirtualMemory");
  hkCreateProcess = (TCreateProcess)util::getFunctionAddress("ntdll", "NtCreateProcess");
  hkCreateSection = (TCreateSection)util::getFunctionAddress("ntdll", "NtCreateSection");
  hkCreateUserThread = (TCreateUserThread)util::getFunctionAddress("ntdll", "RtlCreateUserThread");
  hkGetContextThread = (TGetContextThread)util::getFunctionAddress("ntdll", "NtGetContextThread");
  hkMapViewOfSection = (TMapViewOfSection)util::getFunctionAddress("ntdll", "NtMapViewOfSection");
  hkQueryInformationProcess = (TQueryInformationProcess)util::getFunctionAddress("ntdll", "NtQueryInformationProcess");
  hkResumeProcess = (TResumeProcess)util::getFunctionAddress("ntdll", "NtResumeProcess");
  hkSetContextThread = (TSetContextThread)util::getFunctionAddress("ntdll", "NtSetContextThread");
  hkSuspendProcess = (TSuspendProcess)util::getFunctionAddress("ntdll", "NtSuspendProcess");
  hkUnmapViewOfSection = (TUnmapViewOfSection)util::getFunctionAddress("ntdll", "ZwUnmapViewOfSection");
  hkWriteVirtualMemory = (TWriteVirtualMemory)util::getFunctionAddress("ntdll", "NtWriteVirtualMemory");
}
