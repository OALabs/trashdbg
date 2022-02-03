import ctypes

def RaiseIfZero(result, func = None, arguments = ()):
    """
    Error checking for most Win32 API calls.
    The function is assumed to return an integer, which is C{0} on error.
    In that case the C{WindowsError} exception is raised.
    """
    if not result:
        raise ctypes.WinError()
    return result