import ctypes
import win32api
import win32security

import win32types
import win32utils



# Copy paste from winappdbg: https://github.com/MarioVilas/winappdbg
# BOOL WINAPI ReadProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __out  LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesRead
# );
# + Maybe change page permissions before trying to read?
# Thomas: Page permissions might be a problem only for edge cases, like MEM_NOACCESS
def read(hProcess, lpBaseAddress, nSize):
    _ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
    _ReadProcessMemory.argtypes = [win32types.HANDLE, 
                                    win32types.LPVOID, 
                                    win32types.LPVOID, 
                                    win32types.SIZE_T, 
                                    win32types.POINTER(win32types.SIZE_T)]
    _ReadProcessMemory.restype  = bool

    lpBuffer            = ctypes.create_string_buffer(b'', nSize)
    lpNumberOfBytesRead = win32types.SIZE_T(0)
    success = _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead))
    if not success and ctypes.WinError().errno != win32types.ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return (lpBuffer.raw)[:lpNumberOfBytesRead.value]


# BOOL WINAPI WriteProcessMemory(
#   __in   HANDLE hProcess,
#   __in   LPCVOID lpBaseAddress,
#   __in   LPVOID lpBuffer,
#   __in   SIZE_T nSize,
#   __out  SIZE_T* lpNumberOfBytesWritten
# );
def write(hProcess, lpBaseAddress, lpBuffer):
    _WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    _WriteProcessMemory.argtypes = [win32types.HANDLE, 
                                    win32types.LPVOID, 
                                    win32types.LPVOID, 
                                    win32types.SIZE_T, 
                                    win32types.POINTER(win32types.SIZE_T)]
    _WriteProcessMemory.restype  = bool

    nSize                   = len(lpBuffer)
    lpBuffer                = ctypes.create_string_buffer(lpBuffer)
    lpNumberOfBytesWritten  = win32types.SIZE_T(0)
    success = _WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesWritten))
    if not success and ctypes.WinError().errno != win32types.ERROR_PARTIAL_COPY:
        raise ctypes.WinError()
    return lpNumberOfBytesWritten.value


# SIZE_T WINAPI VirtualQueryEx(
#   __in      HANDLE hProcess,
#   __in_opt  LPCVOID lpAddress,
#   __out     PMEMORY_BASIC_INFORMATION lpBuffer,
#   __in      SIZE_T dwLength
# );
def VirtualQueryEx(hProcess, lpAddress):
    _VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
    _VirtualQueryEx.argtypes = [win32types.HANDLE, 
                                win32types.LPVOID, 
                                win32types.POINTER(win32types.MEMORY_BASIC_INFORMATION), 
                                win32types.SIZE_T]
    _VirtualQueryEx.restype  = win32types.SIZE_T

    lpBuffer  = win32types.MEMORY_BASIC_INFORMATION()
    dwLength  = ctypes.sizeof(win32types.MEMORY_BASIC_INFORMATION)
    success   = _VirtualQueryEx(hProcess, lpAddress, ctypes.byref(lpBuffer), dwLength)
    if success == 0:
        raise ctypes.WinError()
    return lpBuffer


# BOOL WINAPI VirtualProtectEx(
#   __in   HANDLE hProcess,
#   __in   LPVOID lpAddress,
#   __in   SIZE_T dwSize,
#   __in   DWORD flNewProtect,
#   __out  PDWORD lpflOldProtect
# );
def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect = win32types.PAGE_EXECUTE_READWRITE):
    _VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
    _VirtualProtectEx.argtypes = [  win32types.HANDLE, 
                                    win32types.LPVOID, 
                                    win32types.SIZE_T, 
                                    win32types.DWORD, 
                                    win32types.PDWORD]
    _VirtualProtectEx.restype  = bool
    _VirtualProtectEx.errcheck = win32utils.RaiseIfZero

    flOldProtect = win32types.DWORD(0)
    _VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, ctypes.byref(flOldProtect))
    return flOldProtect.value



