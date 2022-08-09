#pragma once

class hkProcess;
struct hkShellCode;

namespace hk_local {

bool hollowTarget(DWORD PID = 0) noexcept;							// main hollow target function

void* mapCode(hkProcess* pTarget, hkShellCode* pCode) noexcept;		// create shellcode-filled section in target's memory, return: memory view ptr
DWORD injectAtEntry(hkProcess* pTarget, void* pCodeView) noexcept;	// inject code at entry point of the target's image

}  // namespace hk_local