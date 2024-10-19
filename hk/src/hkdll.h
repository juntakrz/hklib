#pragma once

namespace hk_dll {

void inject(DWORD PID = 0) noexcept;    // injects DLL and fills global variables
void eject() noexcept;                  // ejects DLL from the target process

/*
 * Calls function of an injected DLL.
 * If CALL_NO_CLOSE flag is set - will not automatically shut down the thread
 * and will return its handle and id. Optional: provide an argument (can be an
 * array of char) and its size to send it to a remote thread
 */
DWORD call(LPCSTR function, HANDLE& outHThread, DWORD& outIdThread,
              DWORD flags = 0, PBYTE pArg = nullptr,
              DWORD sizeArg = 0) noexcept;

uint64_t getBaseAddr() noexcept;        // base address of the injected DLL
DWORD getExportOffset(
    LPCSTR funcName) noexcept;          // address of declared export function
                                        // (requires inject() first)
}  // namespace hk_dll