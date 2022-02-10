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
# base_addres:{name, path, base, end, size, entrypoint, exports{}}
target_modules = {}
# bp_address:{original_byte, singleshot}
breakpoint_table = {}
# bp_address:{singleshot}
hardware_breakpoint_table = {}

# Global excpetion for our debugger
class TrashDBGError(Exception):
    pass


def add_software_breakpoint(bp_address, singleshot=True):
    # Check to see if bp already exists
    if bp_address in breakpoint_table.keys():
        raise TrashDBGError(f"Breakpoint already exists")
    # Read the byte we will replace with a bp
    original_byte = win32memory.read(target_handl, bp_address, 1)
    # Write our bp
    bytes_written = win32memory.write(target_handl, bp_address, b'\xcc')
    if bytes_written != 1:
        raise TrashDBGError(f"Unable to write breakpoint at {hex(bp_address)}")
    # Save our bp to the breakpoint table
    breakpoint_table[bp_address] = {"original_byte":original_byte, "singleshot":singleshot}
    return True


def add_hardware_breakpoint(thead_id, bp_address, singleshot=True):
    # Check to see if bp already exists
    if bp_address in hardware_breakpoint_table.keys():
        raise TrashDBGError(f"Hardware breakpoint already exists")
    if len(hardware_breakpoint_table.keys()) == 4:
        # We are only allowed max 4 hw breakpoints and it's full
        raise TrashDBGError(f"Hardware breakpoint registers full")
    # Set bp using context 
    # Get the context 
    dwThreadId = thead_id
    # Get a thread handle
    hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, dwThreadId)
    # Get the thread context
    context = win32process.GetThreadContext(hThread)
    # Set debug regsiters
    # TODO ******

    set_context_status = win32process.SetThreadContext(hThread, context)

    # Save our bp to the breakpoint table
    hardware_breakpoint_table[bp_address] = {"singleshot":singleshot}
    return True


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
        # TODO: For some reason we don't get all of the exports here
        #       we are missing NtWriteFile from ntdll - something to do with max exports??
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
    return win32types.DBG_CONTINUE


def handle_unload_dll(pEvent):
    dll_base_address = pEvent.u.UnloadDll.lpBaseOfDll
    dll_info = target_modules.get(dll_base_address, None)
    if dll_info is None:
        print(f"Error unloading DLL at base {pEvent.u.UnloadDll.lpBaseOfDll} - we aren't tracking this DLL in our target_modules")
        return
    # Print some info about the unloaded DLL
    print(f"Unloaded DLL {dll_info.get('path','NaN')}")
    target_modules.pop(dll_base_address)
    return win32types.DBG_CONTINUE


def handle_software_breakpoint(pEvent):
    exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress
    if exception_address in breakpoint_table.keys():
        # Handle our breakpoint
        bp_info = breakpoint_table[exception_address]
        print(f"Breakpoint hit at {hex(exception_address)}")
        # Get the context 
        dwThreadId = pEvent.dwThreadId
        # Get a thread handle
        hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, dwThreadId)
        # Get the thread context
        context = win32process.GetThreadContext(hThread)
        print(f"EIP: {hex(context.Eip)}")
        # Set EIP back one byte for the bp
        context.Eip = context.Eip - 1
        set_context_status = win32process.SetThreadContext(hThread, context)
        if bp_info.get("singleshot", True):
            # This is a single shot bp so remove it
            # Restore original byte
            original_byte = bp_info.get("original_byte", None)
            if original_byte is None:
                raise TrashDBGError("Breakpoint handling error, no original byte to restore")
            bytes_written = win32memory.write(target_handl, exception_address, original_byte)
            if bytes_written != 1:
                raise TrashDBGError("Breakpoint handling error, unable to restore original byte")
            # Remove the breakpoint entry from the table
            breakpoint_table.pop(exception_address)
            print("Removed bp continuing execution")
        else:
            # We need to execute and then restore the bp 
            raise TrashDBGError("ERROR TODO: we haven't handled non-singleshot bp yet")
        dwStatus = win32types.DBG_CONTINUE
    else:
        # SUPER HACK!!
        # use this free bp to set our own bp
        # Test breakpoint -- set a bp on ntdll.dll : ZwWriteFile
        if exception_address == 0x77c41ba2:
            # Find ntdll
            for module_address in target_modules.keys():
                if target_modules[module_address].get('name','') == 'ntdll.dll':
                    exports =  target_modules[module_address].get('exports',{})
                    for export_address in exports.keys():
                        if b'ZwWriteFile'.lower() == exports[export_address].get('name', b'').lower():
                            print("Adding bp on ZwWriteFile")
                            bp_set_status = add_software_breakpoint(export_address)
        # Not our breakpoint don't handle
        print(f"Not our breakpoint at {hex(exception_address)}")
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    return dwStatus


def handle_hardware_breakpoint(pEvent):
    exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress
    if exception_address in hardware_breakpoint_table.keys():
        # Handle our breakpoint
        print(f"Hardware Breakpoint hit at {hex(exception_address)}")
        dwStatus = win32types.DBG_CONTINUE
    else:
        # Not our breakpoint don't handle
        print(f"Not our hardware breakpoint at {hex(exception_address)}")
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    return dwStatus


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
                    dwStatus = handle_software_breakpoint(pEvent)
                elif exception_code == win32types.EXCEPTION_GUARD_PAGE: 
                    print(f"GUARD_PAGE exception at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
                elif exception_code == win32types.EXCEPTION_SINGLE_STEP: 
                    # Hardware breakpoint
                    print(f"Hardware breakpoint at {hex(exception_address)}")
                    # We are not handling this right now
                    dwStatus = handle_hardware_breakpoint(pEvent)
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
                dwStatus = handle_load_dll(pEvent)
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
                dwStatus = handle_unload_dll(pEvent)
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

