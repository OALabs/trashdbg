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
import win32debug

# Globals for tracking our target
target_handl = None 
target_pid = None
# base_addres:{name, path, base, end, size, entrypoint, exports[]}
target_modules = {}
# bp_address:{original_byte, singleshot}
breakpoint_table = {}
# bp_reg_index:{address':bp_address, 'type':bp_type,  'size':bp_size}
# to make things easy ware setting hw breakpoints across all threads
# no thread specific breakpoints
hardware_breakpoint_table = {}
# thread tracker
process_threads = []

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


def add_hardware_breakpoint(bp_address, bp_reg_index, bp_type, bp_size):
    # Check to see if bp already exists
    for current_bp_reg in hardware_breakpoint_table:
        if current_bp_reg.get('address', None) == bp_address:
            # The address is set
            raise TrashDBGError(f"Hardware breakpoint already exists in Dr{current_bp_reg}")
    if len(hardware_breakpoint_table.keys()) == 4:
        # We are only allowed max 4 hw breakpoints and it's full
        raise TrashDBGError(f"Hardware breakpoint registers full")
    # Set bp for each thread
    for thread_id in process_threads:
        print(f"Set hardware breakpoint for thread {thread_id} at {hex(bp_address)}")
        # Get a thread handle
        hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, thread_id)
        # Get the thread context
        context = win32process.GetThreadContext(hThread)
        # Set debug regsiters
        # TODO ******
        # https://bitbucket.org/mrexodia/enigmahwid/src/master/hwbp.cpp
        # Assumptions
        # - set the dr0-3 register with bp address
        # - set dr7 struct[dr0-3] with MODE_LOCAL, bp size, bp type
        #print(context)
        win32debug.DebugRegister.set_bp(context, bp_reg_index, bp_address, bp_type, bp_size)
        set_context_status = win32process.SetThreadContext(hThread, context)
        # Save our bp to the breakpoint table
        hardware_breakpoint_table[bp_reg_index] = {'address':bp_address, 'type':bp_type,  'size':bp_size}
        # Close our thread handle
        win32process.CloseHandle(hThread)
    return True


def remove_hardware_breakpoint(bp_reg_index):
    # Check to see if bp exists
    if bp_reg_index not in hardware_breakpoint_table.keys():
        raise TrashDBGError(f"No hardware breakpoint set for {bp_reg_index}")
    # Remove our bp from the breakpoint table
    hardware_breakpoint_table.pop(bp_reg_index)
    # Clear bp for each thread
    for thread_id in process_threads:
        print(f"Clear hardware breakpoint for thread {thread_id} at index {bp_reg_index}")
        # Get a thread handle
        hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, thread_id)
        # Get the thread context
        context = win32process.GetThreadContext(hThread)
        # Clear bp from context
        win32debug.DebugRegister.clear_bp(context, bp_reg_index)
        set_context_status = win32process.SetThreadContext(hThread, context)
        # Close our thread handle
        win32process.CloseHandle(hThread)
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
        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_address = dll_base_address + exp.address
            export_name = exp.name
            export_ord = exp.ordinal
            exports.append({'name':export_name, 'ord':export_ord, 'address':export_address})

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
    # TEST: If the module is ntdll then add a bp on ZwWriteFile
    # Find ntdll
    if dll_name == 'ntdll.dll':
        for module_address in target_modules.keys():
            if target_modules[module_address].get('name','') == 'ntdll.dll':
                exports =  target_modules[module_address].get('exports',[])
                for export in exports:
                    if b'ZwWriteFile'.lower() == export.get('name', b'').lower():
                        export_address = export.get('address', None)
                        if export_address is None:
                            raise TrashDBGError(f"Export address for ZwWriteFile is None")
                        # print("Adding bp on ZwWriteFile")
                        # bp_set_status = add_software_breakpoint(export_address)
                        print(f"Setting hw breakpoint")
                        add_hardware_breakpoint(#0x77C3C0A8, 
                                                export_address,
                                                0, 
                                                win32debug.BREAK_ON_EXECUTION, 
                                                win32debug.WATCH_BYTE)
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
        # In x64dbg it's called 'System breakpoint'
        # NOTE: The hardware bp registers are restored after this bp
        # so we cannot add a hw bp here
        if exception_address == 0x77c41ba2:
            print("System breakpoint")
            # # Find ntdll
            # for module_address in target_modules.keys():
            #     if target_modules[module_address].get('name','') == 'ntdll.dll':
            #         exports =  target_modules[module_address].get('exports',[])
            #         for export in exports:
            #             if b'ZwWriteFile'.lower() == export.get('name', b'').lower():
            #                 export_address = export.get('address', None)
            #                 if export_address is None:
            #                     raise TrashDBGError(f"Export address for ZwWriteFile is None")
            #                 # print("Adding bp on ZwWriteFile")
            #                 # bp_set_status = add_software_breakpoint(export_address)
            #                 print(f"Setting hw breakpoint")
            #                 print(f"This is our thread: {pEvent.dwThreadId}")
            #                 add_hardware_breakpoint(#0x77C3C0A8, 
            #                                         export_address,
            #                                         0, 
            #                                         win32debug.BREAK_ON_EXECUTION, 
            #                                         win32debug.WATCH_BYTE)

        # Not our breakpoint don't handle
        print(f"Not our breakpoint at {hex(exception_address)}")
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    return dwStatus


def handle_hardware_breakpoint(pEvent):
    exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress
    # Find bp 
    hwbp_reg = None
    hwbp_reg_index = None
    for current_hwbp_reg_index in hardware_breakpoint_table.keys():
        current_hwbp_reg = hardware_breakpoint_table[current_hwbp_reg_index]
        if current_hwbp_reg.get('address', None) == exception_address:
            hwbp_reg = current_hwbp_reg
            hwbp_reg_index = current_hwbp_reg_index
            break
    # Check to see if we found our bp
    if hwbp_reg is None:
        # Not our breakpoint don't handle
        print(f"Not our hardware breakpoint at {hex(exception_address)}")
        return win32types.DBG_EXCEPTION_NOT_HANDLED

    # Handle our breakpoint
    print(f"Hardware breakpoint hit at {hex(exception_address)}")
    # Remove hardware breakpoint
    bp_remove_status = remove_hardware_breakpoint(hwbp_reg_index)
    return win32types.DBG_CONTINUE

   



def handle_new_thread(pEvent):
    global process_threads
    thread_id = pEvent.dwThreadId
    # add thread id to thread tracker
    process_threads.append(thread_id)
    # TODO: add any existing hardware bp to the thread
    for current_bp_reg_index in hardware_breakpoint_table.keys():
        current_bp_reg = hardware_breakpoint_table[current_bp_reg_index]
        print(f"Set hardware breakpoint for new thread {thread_id} at {hex(current_bp_reg.get('address',None))}")
        # Get a thread handle
        hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, thread_id)
        # Get the thread context
        context = win32process.GetThreadContext(hThread)
        # Set debug regsiters
        # TODO ******
        # https://bitbucket.org/mrexodia/enigmahwid/src/master/hwbp.cpp
        # Assumptions
        # - set the dr0-3 register with bp address
        # - set dr7 struct[dr0-3] with MODE_LOCAL, bp size, bp type
        #print(context)
        win32debug.DebugRegister.set_bp(context, 
                                        current_bp_reg_index, 
                                        current_bp_reg.get('address'), 
                                        current_bp_reg.get('type'), 
                                        current_bp_reg.get('size'))
        set_context_status = win32process.SetThreadContext(hThread, context)
        # Close our thread handle
        win32process.CloseHandle(hThread)


def handle_exit_thread(pEvent):
    global process_threads
    thread_id = pEvent.dwThreadId
    # remove thread id from tracker
    process_threads.remove(thread_id)


def main():
    global target_handl, target_pid, process_threads
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
    process_threads.append(pProcessInfo.dwThreadId)
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
                handle_new_thread(pEvent)
            elif pEvent.dwDebugEventCode == win32types.EXIT_THREAD_DEBUG_EVENT:
                print(f"EXIT_THREAD_DEBUG_EVENT")
                handle_exit_thread(pEvent)
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

