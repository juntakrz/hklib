#pragma once

class hkTarget;
struct hkShellCode;

namespace hk_local {

bool hollowTarget(DWORD PID = 0) noexcept;							// main hollow target function

void* injectCode(hkTarget* pTarget, hkShellCode* pCode) noexcept;	// create section in memory filled with shellcode and ready to be injected

}  // namespace hk_local