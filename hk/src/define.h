#pragma once

#include "pch.h"

#define LOG(x)		std::cout << x << "\n"
#define wLOG(x)		std::wcout << x << "\n"
#define LOGn(x)		std::cout << x
#define wLOGn(x)	std::wcout << x

#define ERRCHK                  \
  { DWORD error = GetLastError();	\
  if (error) { printf("Error code: %d\n\nPress ANY key to exit.\n", error); _getch(); exit(error); }}

#define NULL_THREAD *((HANDLE*)0)
#define NULL_ID *((DWORD*)0)

enum callFlags {
  CALL_NORMAL		= 0,		// standard call
  CALL_NO_WAIT		= 1 << 0,	// don't wait for thread
  CALL_NO_CLOSE		= 1 << 1,	// don't close handle automatically
  CALL_NO_RETURN	= 1 << 2	// don't return a DWORD result from thread
};

/* WinAPI internal function ptr aliases (should work for both Nt* and Zw* functions)
* EXAMPLE:
* HANDLE hProcess = <some target process>
* TSuspendProcess hkSuspendProcess = (TSuspendProcess)hk_util::procAddr("ntdll", "NtSuspendProcess");
* hkSuspendProcess(hProcess);
*/

using TCreateSection = NTSTATUS(NTAPI *)(
    OUT PHANDLE SectionHandle, IN ULONG DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize, IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes, IN OPTIONAL HANDLE FileHandle);

using TMapViewOfSection = NTSTATUS(NTAPI *)(
    IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize,
    IN DWORD InheritDisposition, IN ULONG AllocationType,
    IN ULONG Win32Protect);

using TUnmapViewOfSection = NTSTATUS(NTAPI *)(IN HANDLE ProcessHandle, IN PVOID BaseAddr);

using TSetContextThread = NTSTATUS(NTAPI *)(IN HANDLE ThreadHandle, IN PCONTEXT pContext);

using TGetContextThread = NTSTATUS(NTAPI *)(IN HANDLE ThreadHandle, OUT PCONTEXT pContext);

using TQueryInformationProcess = NTSTATUS(NTAPI *)(
    IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength);

using TCreateUserThread =
    NTSTATUS(NTAPI *)(IN HANDLE ProcessHandle,
                     IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,
                     IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits,
                     IN OUT PULONG StackReserved, IN OUT PULONG StackCommit,
                     IN PVOID StartAddress, IN OPTIONAL PVOID StartParameter,
                     OUT PHANDLE ThreadHandle, OUT CLIENT_ID* ClientID);

using TSuspendProcess = NTSTATUS(NTAPI *)(IN HANDLE ProcessHandle);
using TResumeProcess = NTSTATUS(NTAPI *)(IN HANDLE ProcessHandle);

/* * */