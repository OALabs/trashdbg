import ctypes
import win32api
import win32security


# Setup Win API calls
GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.rettype = ctypes.c_long


class ElevateError(Exception):
    pass


def se_debug():
        try:
            flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
            id = win32security.LookupPrivilegeValue(None, "seDebugPrivilege")
            newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
            if not win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges):
                # Raise error
                raise ElevateError(ctypes.WinError().strerro)
            else:
                return True
        except Exception as e:
            raise ElevateError(str(e))