import sys
import os
import time
import ctypes
import msvcrt

import win32types
import elevate


def main():
    # Get target path
    target_path = sys.argv[1]
    print(f"Debugging:{target_path}")

    # Get debug privs
    if not elevate.se_debug():
        print("Failed to elevate privs, exiting!")
        sys.exit(1)

    # Create target process
    pStartupInfo = win32types.STARTUPINFO()
    pProcessInfo = win32types.PROCESS_INFORMATION()
    proc_status = ctypes.windll.kernel32.CreateProcessW(target_path,
                                                        None,
                                                        None,
                                                        None,
                                                        False,
                                                        win32types.DEBUG_PROCESS,
                                                        None,
                                                        None,
                                                        ctypes.byref(pStartupInfo),
                                                        ctypes.byref(pProcessInfo))

    if not proc_status:
        print(f"Cannot create target process:{ctypes.WinError().strerror}")
        sys.exit(1)

    hProcess = pProcessInfo.hProcess
    print(f"Process started with PID:{pProcessInfo.dwProcessId}")
    print(f"Press ENTER to quit debug loop...")

    # This is our debug event loop
    # We keep processing debug events until the target has exited
    # or the user presses ENTER
    while True:
        pEvent = win32types.DEBUG_EVENT()
        dwStatus = win32types.DBG_CONTINUE

        # Wait for a debug event from the target
        # We timeout to allow the loop a chance to check for user input
        if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(pEvent), 100):
            # We have a debug event to process
            if pEvent.dwDebugEventCode == win32types.EXCEPTION_DEBUG_EVENT: 
                # Obtain the exception code
                exception_code = pEvent.u.Exception.ExceptionRecord.ExceptionCode
                exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress

                # Handle debug exception event
                if exception_code == win32types.EXCEPTION_ACCESS_VIOLATION:
                    print(f"Access violation detected at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.EXCEPTION_BREAKPOINT: 
                    # Soft breakpoint
                    print(f"Software breakpoint at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.EXCEPTION_GUARD_PAGE: 
                    print(f"GUARD_PAGE exception at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.EXCEPTION_SINGLE_STEP: 
                    # Hardware breakpoint
                    print(f"Hardware breakpoint at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.STATUS_WX86_BREAKPOINT:
                    # Hardware breakpoint
                    print(f"WOW64 software breakpoint (32bit code) - why are you useing x64 debugger for 32-bit code??")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.STATUS_WX86_SINGLE_STEP:
                    # Hardware breakpoint
                    print(f"WOW64 hardware breakpoint (32bit code) - why are you useing x64 debugger for 32-bit code??")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                else:
                    # What happened here?!
                    print(f"!! Unknown debug exception: {exception_code}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
            elif pEvent.dwDebugEventCode == win32types.LOAD_DLL_DEBUG_EVENT:
                print(f"LOAD_DLL_DEBUG_EVENT")
            elif pEvent.dwDebugEventCode == win32types.EXIT_PROCESS_DEBUG_EVENT:
                print(f"EXIT_PROCESS_DEBUG_EVENT")
                break
            elif pEvent.dwDebugEventCode == win32types.CREATE_PROCESS_DEBUG_EVENT:
                print(f"CREATE_PROCESS_DEBUG_EVENT")
            elif pEvent.dwDebugEventCode == win32types.CREATE_THREAD_DEBUG_EVENT:
                print(f"CREATE_THREAD_DEBUG_EVENT")
            elif pEvent.dwDebugEventCode == win32types.EXIT_THREAD_DEBUG_EVENT:
                print(f"EXIT_THREAD_DEBUG_EVENT")
            elif pEvent.dwDebugEventCode == win32types.UNLOAD_DLL_DEBUG_EVENT:
                print(f"UNLOAD_DLL_DEBUG_EVENT")
            elif pEvent.dwDebugEventCode == win32types.OUTPUT_DEBUG_STRING_EVENT:
                print(f"OUTPUT_DEBUG_STRING_EVENT")
            elif pEvent.dwDebugEventCode == win32types.RIP_EVENT:
                print(f"RIP_EVENT")
                break

        # Check for user ENTER key on console 
        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break

        # Continue target thread
        ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)



if __name__ == '__main__':
    main()

