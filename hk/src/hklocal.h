#pragma once

class hkProcess;
struct hkShellCode;

namespace hk_local {

bool hollowTarget(DWORD PID = 0) noexcept;							// main hollow target function

// Create shellcode-filled section in target's memory, return: memory view ptr
void* mapShellCodeIntoTargetProcess(hkProcess* pTarget, hkShellCode* pCode) noexcept;

// Inject code at entry point of the target's image
DWORD injectAtEntry(hkProcess* pTarget, void* pCodeView) noexcept;

}  // namespace hk_local