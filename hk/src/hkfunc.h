#pragma once

#include "define.h"

/* WinAPI internal function ptr aliases (should work for both Nt* and Zw* functions)
* EXAMPLE:
* HANDLE hProcess = <some target process>
* TSuspendProcess hkSuspendProcess = (TSuspendProcess)util::getFunctionAddress("ntdll", "NtSuspendProcess");
* hkSuspendProcess(hProcess);
*/
using TCreateProcess = NTSTATUS(NTAPI*)(
  OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess,
  IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN HANDLE ParentProcess,
  IN BOOLEAN InheritObjectTable, IN OPTIONAL HANDLE SectionHandle,
  IN OPTIONAL HANDLE DebugPort, IN OPTIONAL HANDLE ExceptionPort);

using TCreateSection = NTSTATUS(NTAPI*)(
  OUT PHANDLE SectionHandle, IN ULONG DesiredAccess,
  IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
  IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG SectionPageProtection,
  IN ULONG AllocationAttributes, IN OPTIONAL HANDLE FileHandle);

using TMapViewOfSection = NTSTATUS(NTAPI*)(
  IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress,
  IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize,
  IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize,
  IN DWORD InheritDisposition, IN ULONG AllocationType,
  IN ULONG Win32Protect);

using TUnmapViewOfSection = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PVOID BaseAddr);

using TSetContextThread = NTSTATUS(NTAPI*)(IN HANDLE ThreadHandle, IN PCONTEXT pContext);

using TGetContextThread = NTSTATUS(NTAPI*)(IN HANDLE ThreadHandle, OUT PCONTEXT pContext);

using TQueryInformationProcess = NTSTATUS(NTAPI*)(
  IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength,
  OUT OPTIONAL PULONG ReturnLength);

using TCreateUserThread =
NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle,
  IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,
  IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits,
  IN OUT PULONG StackReserved, IN OUT PULONG StackCommit,
  IN PVOID StartAddress, IN OPTIONAL PVOID StartParameter,
  OUT PHANDLE ThreadHandle, OUT CLIENT_ID* ClientID);

using TSuspendProcess = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle);
using TResumeProcess = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle);

using TAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress,
  ULONG_PTR ZeroBits, PSIZE_T RegionSize,
  ULONG AllocationType, ULONG Protect);

using TWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, LPVOID BaseAddress, LPVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

using TCreateThreadEx = NTSTATUS(NTAPI*) (OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle,
  IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits,
  IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);

extern TAllocateVirtualMemory hkAllocateVirtualMemory;
extern TCreateProcess hkCreateProcess;
extern TCreateSection hkCreateSection;
extern TCreateThreadEx hkCreateThreadEx;
extern TCreateUserThread hkCreateUserThread;
extern TGetContextThread hkGetContextThread;
extern TMapViewOfSection hkMapViewOfSection;
extern TQueryInformationProcess hkQueryInformationProcess;
extern TResumeProcess hkResumeProcess;
extern TSetContextThread hkSetContextThread;
extern TSuspendProcess hkSuspendProcess;
extern TUnmapViewOfSection hkUnmapViewOfSection;
extern TWriteVirtualMemory hkWriteVirtualMemory;

void initializeWinAPIFunctions();
std::string decryptFunctionName(const uint8_t* inEncryptedArray, const size_t inArraySize);