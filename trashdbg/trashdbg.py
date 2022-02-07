import sys
import os
import time
import ctypes
import msvcrt
import pefile

import win32types
import win32elevate
import win32process
import win32memory

# Globals for tracking our target
target_handl = None 
target_pid = None
# {
#    base_addres:{name, path, base, end, size, entrypoint, exports{}}
# }
target_modules = {}





def handle_load_dll(pEvent):
    global target_modules

    try:
        # cfam solution for dll that is not fully loaded
        file_path_buffer_size = win32types.MAX_PATH
        file_path_buffer = ctypes.create_unicode_buffer(u"", win32types.MAX_PATH + 1)
        ret = ctypes.windll.kernel32.GetFinalPathNameByHandleW(
          pEvent.u.LoadDll.hFile,            # [in]  HANDLE hFile,
          file_path_buffer,                       # [out] LPWSTR lpszFilePath,
          file_path_buffer_size,                  # [in]  DWORD  cchFilePath,
          win32types.FILE_NAME_NORMALIZED,                   # [in]  DWORD  dwFlags
        )
        if not ret:
            print(f"Error LOAD_DLL_DEBUG_EVENT: GetFinalPathNameByHandleW failed with {ctypes.WinError().strerror}")
            return
        dll_path = file_path_buffer.value
        # Load PE file from disk and get more info
        pe = pefile.PE(dll_path, fast_load=True)
        dll_base_address = pEvent.u.LoadDll.lpBaseOfDll
        dll_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint + dll_base_address
        dll_end_address = pe.sections[-1].Misc_VirtualSize + pe.sections[-1].VirtualAddress + dll_base_address
        dll_virtual_size = dll_end_address - dll_base_address
        dll_name = os.path.basename(dll_path)

        # Print some info about the DLL
        print(f"DLL loaded {dll_path}")
        print(f"\tName: {dll_name}")
        print(f"\tBase: {hex(dll_base_address)}")
        print(f"\tEnd: {hex(dll_end_address)}")
        print(f"\tSize: {dll_virtual_size}")
        print(f"\tEntry Point: {hex(dll_entrypoint)}")

        # Get the DLL exports
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        exports = {}
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_address = dll_base_address + exp.address
            export_name = exp.name
            export_ord = exp.ordinal
            exports[export_address]  = {'name':export_name, 'ord':export_ord}

        # Populate our DLL list
        target_modules[dll_base_address] = {'name':dll_name, 
                                            'path':dll_path, 
                                            'base':dll_base_address, 
                                            'end_address':dll_end_address,
                                            'size':dll_virtual_size,
                                            'entrypoint':dll_entrypoint, 
                                            'exports':exports}
    except Exception as e:
        print(f"Error reading loaded DLL at base {hex(pEvent.u.LoadDll.lpBaseOfDll)}: {e}")

    # Testing read memory
    # This is just a temporary test to see if we can read the MZ
    # from loaded DLLs
    mz_addr = dll_base_address
    mz_header = win32memory.read(target_handl, mz_addr, 2)
    print(f"!!! TEST mz header {mz_header}")

    # Testing memory write
    # This is just a temporary test to see if we can
    # write 'AA' to the DLL address of MZ + 4 bytes
    # we don't want to overwrite the MZ since that is used by other
    # functions to read the DLL but 4 bytes offset is not used by anything
    mz_off_4_addr = dll_base_address + 4
    pMemoryBasicInformation = win32memory.VirtualQueryEx(target_handl, mz_off_4_addr)
    if (win32types.WRITEABLE & pMemoryBasicInformation.Protect) != 0:
        # It is writable let's change the MZ
        bytes_written = win32memory.write(target_handl, mz_off_4_addr, b'AA')
    else:
        # Not writable let's fix this temporarily
        old_protections = win32memory.VirtualProtectEx(target_handl, mz_off_4_addr, 2, win32types.PAGE_READWRITE)
        bytes_written = win32memory.write(target_handl, mz_off_4_addr, b'AA')
        new_protections = win32memory.VirtualProtectEx(target_handl, mz_off_4_addr, 2, old_protections)


def handle_unload_dll(pEvent):
    dll_base_address = pEvent.u.UnloadDll.lpBaseOfDll
    dll_info = target_modules.get(dll_base_address, None)
    if dll_info is None:
        print(f"Error unloading DLL at base {pEvent.u.UnloadDll.lpBaseOfDll} - we aren't tracking this DLL in our target_modules")
        return
    # Print some info about the unloaded DLL
    print(f"Unloaded DLL {dll_info.get('path','NaN')}")
    target_modules.pop(dll_base_address)


def main():
    global target_handl, target_pid
    # Get target path
    target_path = sys.argv[1]
    print(f"Debugging:{target_path}")

    # Get debug privs
    if not win32elevate.se_debug():
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
    target_handl = hProcess
    target_pid = pProcessInfo.dwProcessId
    print(f"Process started with PID:{pProcessInfo.dwProcessId}")
    print(f"Press ENTER to quit debug loop...")

    # This is our debug event loop
    # We keep processing debug events until the target has exited
    # or the user presses ENTER
    while True:
        pEvent = win32types.DEBUG_EVENT()
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED

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
                handle_load_dll(pEvent)
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
                handle_unload_dll(pEvent)
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

