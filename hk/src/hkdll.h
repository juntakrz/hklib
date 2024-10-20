#pragma once

namespace hk_dll {

// injects DLL and fills global variables
void inject(DWORD PID = 0) noexcept;

// ejects DLL from the target process
void eject() noexcept;

/*
 * Calls function of an injected DLL.
 * If CALL_NO_CLOSE flag is set - will not automatically shut down the thread
 * and will return its handle and id. Optional: provide an argument (can be an
 * array of char) and its size to send it to a remote thread
 */
DWORD call(LPCSTR function, HANDLE& outHThread, DWORD& outIdThread, DWORD flags = 0, PBYTE pArg = nullptr, DWORD sizeArg = 0) noexcept;

// base address of the injected DLL
uint64_t getBaseAddr() noexcept;

// address of declared export function (requires inject() first)
DWORD getExportOffset(LPCSTR funcName) noexcept;
}  // namespace hk_dll