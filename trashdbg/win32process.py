import ctypes
import win32types
import win32api
import win32security
import win32utils


def get_process_modules(ProcessID):
    me32 = win32types.MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(win32types.MODULEENTRY32)
    hModuleSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(win32types.TH32CS_SNAPMODULE, ProcessID)

    ret = ctypes.windll.kernel32.Module32First(hModuleSnap, ctypes.pointer(me32))
    if ret == 0:
        ctypes.windll.kernel32.CloseHandle(hModuleSnap)
        print(f"!!Error Module32First: {ctypes.WinError().strerror}")
        return {}
    modules = {}
    while ret:
        modules[me32.modBaseAddr] = {"name":me32.szModule, 
                                    "path":me32.szExePath, 
                                    "base":me32.modBaseAddr, 
                                    "size":me32.modBaseSize}
        ret = ctypes.windll.kernel32.Module32Next(hModuleSnap, ctypes.pointer(me32))
    ctypes.windll.kernel32.CloseHandle(hModuleSnap)
    return modules

# LOL this def doesn't work on a wow64 process 
# https://stackoverflow.com/questions/3801517/how-to-enum-modules-in-a-64bit-process-from-a-32bit-wow-process
def EnumProcessModulesEx(hProcess, dwFilterFlag = win32types.LIST_MODULES_DEFAULT):
    _EnumProcessModulesEx = ctypes.windll.psapi.EnumProcessModulesEx
    _EnumProcessModulesEx.argtypes = [win32types.HANDLE, 
                                        win32types.LPVOID, 
                                        win32types.DWORD, 
                                        win32types.LPDWORD, 
                                        win32types.DWORD]
    _EnumProcessModulesEx.restype = bool
    _EnumProcessModulesEx.errcheck = win32utils.RaiseIfZero

    size = 0x1000
    lpcbNeeded = win32types.DWORD(size)
    unit = ctypes.sizeof(win32types.HMODULE)
    while 1:
        lphModule = (win32types.HMODULE * (size // unit))()
        _EnumProcessModulesEx(hProcess, ctypes.byref(lphModule), lpcbNeeded, ctypes.byref(lpcbNeeded), dwFilterFlag)
        needed = lpcbNeeded.value
        if needed <= size:
            break
        size = needed
    return [ lphModule[index] for index in range(0, (needed // unit)) ]


def GetModuleFileNameExW(hProcess, hModule = None):
    _GetModuleFileNameExW = ctypes.windll.psapi.GetModuleFileNameExW
    _GetModuleFileNameExW.argtypes = [win32types.HANDLE, win32types.HMODULE, win32types.LPWSTR, win32types.DWORD]
    _GetModuleFileNameExW.restype = win32types.DWORD

    nSize = win32types.MAX_PATH
    while 1:
        lpFilename = ctypes.create_unicode_buffer(u"", nSize)
        nCopied = _GetModuleFileNameExW(hProcess, hModule, lpFilename, nSize)
        if nCopied == 0:
            raise ctypes.WinError()
        if nCopied < (nSize - 1):
            break
        nSize = nSize + win32types.MAX_PATH
    return lpFilename.value


# BOOL WINAPI GetModuleInformation(
#   __in   HANDLE hProcess,
#   __in   HMODULE hModule,
#   __out  LPMODULEINFO lpmodinfo,
#   __in   DWORD cb
# );
def GetModuleInformation(hProcess, hModule, lpmodinfo = None):
    _GetModuleInformation = ctypes.windll.psapi.GetModuleInformation
    _GetModuleInformation.argtypes = [win32types.HANDLE, win32types.HMODULE, win32types.LPMODULEINFO, win32types.DWORD]
    _GetModuleInformation.restype = bool
    _GetModuleInformation.errcheck = win32utils.RaiseIfZero

    if lpmodinfo is None:
        lpmodinfo = MODULEINFO()
    _GetModuleInformation(hProcess, hModule, ctypes.byref(lpmodinfo), ctypes.sizeof(lpmodinfo))
    return lpmodinfo



def get_module_from_base(hProcess, dwBaseAddress):
    # Loop through the process modules until we find our base address
    module_list = EnumProcessModulesEx(hProcess)
    print(module_list)
















