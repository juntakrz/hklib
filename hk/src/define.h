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
using TCreateProcess = NTSTATUS(NTAPI *)(
    OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes, IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable, IN OPTIONAL HANDLE SectionHandle,
    IN OPTIONAL HANDLE DebugPort, IN OPTIONAL HANDLE ExceptionPort);

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

/* WinAPI structures */

// x86-64 Windows PEB structure (as of Windows 10 x64)
struct TPEB64 {                                     // Offset (hex/dec)
  BYTE InheritedAddressSpace;                       // 0x000    0
  BYTE ReadImageFileExecOptions;                    // 0x001    1
  BOOLEAN BeingDebugged;                            // 0x002    2
  BYTE BitField;                                    // 0x003    3
  BYTE Padding0[4];                                 // 0x004    4
  PVOID Mutant;                                     // 0x008    8
  PVOID ImageBaseAddress;                           // 0x010    16
  _PEB_LDR_DATA* Ldr;                               // 0x018    24
  _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;  // 0x020    32
  PVOID SubSystemData;                              // 0x028    40
  PVOID ProcessHeap;                                // 0x030    48
  _RTL_CRITICAL_SECTION* FastPebLock;               // 0x038    56
  _SLIST_HEADER* AtlThunkSListPtr;                  // 0x040    64
  PVOID IFEOKey;                                    // 0x048    72
  DWORD CrossProcessFlags;                          // 0x050    80
  BYTE Padding1[4];                                 // 0x054    84
  PVOID KernelCallbackTable;                        // 0x058    88
  DWORD SystemReserved;                             // 0x060    96
  DWORD AtlThunkSListPtr32;                         // 0x064    100
  PVOID ApiSetMap;                                  // 0x068    104
  DWORD TlsExpansionCounter;                        // 0x070    112
  BYTE Padding2[4];                                 // 0x074    116
  PVOID TlsBitmap;                                  // 0x078    120
  DWORD TlsBitmapBits[2];                           // 0x080    128
  PVOID ReadOnlySharedMemoryBase;                   // 0x088    136
  PVOID SharedData;                                 // 0x090    144
  PVOID* ReadOnlyStaticServerData;                  // 0x098    152
  PVOID AnsiCodePageData;                           // 0x0A0    160
  PVOID OemCodePageData;                            // 0x0A8    168
  PVOID UnicodeCaseTableData;                       // 0x0B0    176
  DWORD NumberOfProcessors;                         // 0x0B8    184
  DWORD NtGlobalFlag;                               // 0x0BC    188
  _LARGE_INTEGER CriticalSectionTimeout;            // 0x0C0    192
  DWORD64 HeapSegmentReserve;                       // 0x0C8    200
  DWORD64 HeapSegmentCommit;                        // 0x0D0    208
  DWORD64 HeapDeCommitTotalFreeThreshold;           // 0x0D8    216
  DWORD64 HeapDeCommitFreeBlockThreshold;           // 0x0E0    224
  DWORD NumberOfHeaps;                              // 0x0E8    232
  DWORD MaximumNumberOfHeaps;                       // 0x0EC    236
  PVOID* ProcessHeaps;                              // 0x0F0    240
  PVOID GdiSharedHandleTable;                       // 0x0F8    248
  PVOID ProcessStarterHelper;                       // 0x100    256
  DWORD GdiDCAttributeList;                         // 0x108    264
  BYTE Padding3[4];                                 // 0x10C    268
  _RTL_CRITICAL_SECTION* LoaderLock;                // 0x110    272
  DWORD OSMajorVersion;                             // 0x118    280
  DWORD OSMinorVersion;                             // 0x11C    284
  WORD OSBuildNumber;                               // 0x120    288
  WORD OSCSDVersion;                                // 0x122    290
  DWORD OSPlatformId;                               // 0x124    292
  DWORD ImageSubsystem;                             // 0x128    296
  DWORD ImageSubsystemMajorVersion;                 // 0x12C    300
  DWORD ImageSubsystemMinorVersion;                 // 0x130    304
  BYTE Padding4[4];                                 // 0x134    308
  DWORD64 ActiveProcessAffinityMask;                // 0x138    312
  DWORD GdiHandleBuffer[60];                        // 0x140    320
  PVOID PostProcessInitRoutine;                     // 0x230    560
  PVOID TlsExpansionBitmap;                         // 0x238    568
  DWORD TlsExpansionBitmapBits[32];                 // 0x240    576
  DWORD SessionId;                                  // 0x2C0    704
  BYTE Padding5[4];                                 // 0x2C4    708
  _ULARGE_INTEGER AppCompatFlags;                   // 0x2C8    712
  _ULARGE_INTEGER AppCompatFlagsUser;               // 0x2D0    720
  PVOID pShimData;                                  // 0x2D8    728
  PVOID AppCompatInfo;                              // 0x2E0    736
  _UNICODE_STRING CSDVersion;                       // 0x2E8    744
  PVOID ActivationContextData;                      // 0x2F8    760     _ACTIVATION_CONTEXT_DATA
  PVOID ProcessAssemblyStorageMap;                  // 0x300    768     _ASSEMBLY_STORAGE_MAP
  PVOID SystemDefaultActivationContextData;         // 0x308    776     _ACTIVATION_CONTEXT_DATA
  PVOID SystemAssemblyStorageMap;                   // 0x310    784     _ASSEMBLY_STORAGE_MAP
  DWORD64 MinimumStackCommit;                       // 0x318    792
  PVOID FlsCallback;                                // 0x320    800     _FLS_CALLBACK_INFO
  _LIST_ENTRY FlsListHead;                          // 0x328    808
  PVOID FlsBitmap;                                  // 0x338    824
  DWORD FlsBitmapBits[4];                           // 0x340    832
  DWORD FlsHighIndex;                               // 0x350    848
  DWORD Unknown;                                    // 0x354    852     FlsHighIndex is 32 bit or 64 bit?
  PVOID WerRegistrationData;                        // 0x358    856
  PVOID WerShipAssertPtr;                           // 0x360    864
  PVOID pUnused;                                    // 0x368    872
  PVOID pImageHeaderHash;                           // 0x370    880
  DWORD TracingFlags;                               // 0x378    888
  BYTE Padding6[4];                                 // 0x37C    892
  DWORD64 CsrServerReadOnlySharedMemoryBase;        // 0x380    896
  DWORD64 TppWorkerpListLock;                       // 0x388    904
  _LIST_ENTRY TppWorkerpList;                       // 0x390    912
  PVOID WaitOnAddressHashTable[128];                // 0x3A0    928
  PVOID TelemetryCoverageHeader;                    // 0x7A0    1952
  DWORD CloudFileFlags;                             // 0x7A8    1960
  DWORD CloudFileDiagFlags;                         // 0x7AC    1964
  CHAR PlaceholderCompatibilityMode;                // 0x7B0    1968
  CHAR PlaceholderCompatibilityModeReserved[7];     // 0x7B1    1969
};