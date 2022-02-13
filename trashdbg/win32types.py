#########################################################################################
##
## Many thanks to Angelo Dell'Aera for all the nice types 
## https://github.com/buffer/maltracer
## 
## I think some of this was lifed from GreyHat Python too??
## 
#########################################################################################

from ctypes import *

# Map the Microsoft types to ctypes for clarity
BYTE      = c_ubyte
BOOL       = c_uint32
WORD      = c_ushort
DWORD     = c_ulong
LONG      = c_ulong
ULONG       = c_uint32
CHAR        = c_char
TCHAR       = CHAR  
LPBYTE      = POINTER(BYTE)
LPWORD      = POINTER(WORD)
LPDWORD     = POINTER(DWORD)
LPULONG     = POINTER(ULONG)
LPLONG      = POINTER(LONG)
PDWORD      = LPDWORD
LPTSTR    = POINTER(c_char)
LPWSTR    = c_wchar_p
PWSTR     = c_wchar_p
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong
HMODULE   = c_void_p
NULL      = c_int(0)


# Windows constants
MAX_PATH = 260
MAX_MODULE_NAME32 = 255

# File Api
FILE_NAME_NORMALIZED = 0
FileNameInfo = 2

# Process constants
PROCESS_CREATE_PROCESS              = 0x0080
PROCESS_CREATE_THREAD               = 0x0002
PROCESS_DUP_HANDLE                  = 0x0040
PROCESS_QUERY_INFORMATION           = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000
PROCESS_SET_INFORMATION             = 0x0200
PROCESS_SET_QUOTA                   = 0x0100
PROCESS_SUSPEND_RESUME              = 0x0800
PROCESS_TERMINATE                   = 0x0001
PROCESS_VM_OPERATION                = 0x0008
PROCESS_VM_READ                     = 0x0010
PROCESS_VM_WRITE                    = 0x0020
SYNCHRONIZE                         = 0x00100000
PROCESS_ALL_ACCESS                  = 0x001F0FFF
CREATE_SUSPENDED                    = 0x00000004


# Module constants
LIST_MODULES_DEFAULT    = 0x00
LIST_MODULES_32BIT      = 0x01
LIST_MODULES_64BIT      = 0x02
LIST_MODULES_ALL        = 0x03


# Debug constants
DEBUG_PROCESS             = 0x00000001
CREATE_NEW_CONSOLE        = 0x00000010
DBG_CONTINUE              = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
INFINITE                  = 0xFFFFFFFF
SE_PRIVILEGE_ENABLED      = 0x00000002
WAIT_TIMEOUT              = 0x00000102


# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001


# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9


# Debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004
STATUS_WX86_BREAKPOINT         = 0x4000001f 
STATUS_WX86_SINGLE_STEP        = 0x4000001E


# Thread constants 
TH32CS_SNAPHEAPLIST       = 0x00000001
TH32CS_SNAPPROCESS        = 0x00000002
TH32CS_SNAPTHREAD         = 0x00000004
TH32CS_SNAPMODULE         = 0x00000008
TH32CS_INHERIT            = 0x80000000
TH32CS_SNAPALL            = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS         = 0x001F03FF

TOKEN_ALL_ACCESS          = 0x000F01FF
STILL_ACTIVE              = 0x00000103

# Thread access rights for OpenThread
THREAD_TERMINATE                 = 0x0001
THREAD_SUSPEND_RESUME            = 0x0002
THREAD_ALERT                     = 0x0004
THREAD_GET_CONTEXT               = 0x0008
THREAD_SET_CONTEXT               = 0x0010
THREAD_SET_INFORMATION           = 0x0020
THREAD_QUERY_INFORMATION         = 0x0040
THREAD_SET_THREAD_TOKEN          = 0x0080
THREAD_IMPERSONATE               = 0x0100
THREAD_DIRECT_IMPERSONATION      = 0x0200
THREAD_SET_LIMITED_INFORMATION   = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800


# Context flags 
CONTEXT_FULL               = 0x00010007
CONTEXT_DEBUG_REGISTERS    = 0x00010010


# Memory permissions
PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004

MEM_COMMIT                = 0x00001000
MEM_RESERVE               = 0x00002000
MEM_DECOMMIT              = 0x00004000
MEM_RELEASE               = 0x00008000
MEM_RESET                 = 0x00080000

MEM_IMAGE                 = 0x01000000
MEM_MAPPED                = 0x00040000
MEM_PRIVATE               = 0x00020000

# Memory page permissions
PAGE_NOACCESS             = 0x00000001
PAGE_READONLY             = 0x00000002
PAGE_READWRITE            = 0x00000004
PAGE_WRITECOPY            = 0x00000008
PAGE_EXECUTE              = 0x00000010
PAGE_EXECUTE_READ         = 0x00000020
PAGE_EXECUTE_READWRITE    = 0x00000040
PAGE_EXECUTE_WRITECOPY    = 0x00000080
PAGE_GUARD                = 0x00000100
PAGE_NOCACHE              = 0x00000200
PAGE_WRITECOMBINE         = 0x00000400

MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000
VIRTUAL_MEM = (MEM_COMMIT | MEM_RESERVE)


READABLE =      (
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READONLY           |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
                )

WRITEABLE =     (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
                )

COPY_ON_WRITE = (
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_WRITECOPY
                )

EXECUTABLE =    (
                PAGE_EXECUTE            |
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
                )

EXECUTABLE_AND_WRITEABLE = (
                            PAGE_EXECUTE_READWRITE  |
                            PAGE_EXECUTE_WRITECOPY
                            )



# Error codes
ERROR_SUCCESS                       = 0
ERROR_INVALID_FUNCTION              = 1
ERROR_FILE_NOT_FOUND                = 2
ERROR_PATH_NOT_FOUND                = 3
ERROR_ACCESS_DENIED                 = 5
ERROR_INVALID_HANDLE                = 6
ERROR_NOT_ENOUGH_MEMORY             = 8
ERROR_INVALID_DRIVE                 = 15
ERROR_NO_MORE_FILES                 = 18
ERROR_BAD_LENGTH                    = 24
ERROR_HANDLE_EOF                    = 38
ERROR_HANDLE_DISK_FULL              = 39
ERROR_NOT_SUPPORTED                 = 50
ERROR_FILE_EXISTS                   = 80
ERROR_INVALID_PARAMETER             = 87
ERROR_BUFFER_OVERFLOW               = 111
ERROR_DISK_FULL                     = 112
ERROR_CALL_NOT_IMPLEMENTED          = 120
ERROR_SEM_TIMEOUT                   = 121
ERROR_INSUFFICIENT_BUFFER           = 122
ERROR_INVALID_NAME                  = 123
ERROR_MOD_NOT_FOUND                 = 126
ERROR_PROC_NOT_FOUND                = 127
ERROR_DIR_NOT_EMPTY                 = 145
ERROR_BAD_THREADID_ADDR             = 159
ERROR_BAD_ARGUMENTS                 = 160
ERROR_BAD_PATHNAME                  = 161
ERROR_ALREADY_EXISTS                = 183
ERROR_INVALID_FLAG_NUMBER           = 186
ERROR_ENVVAR_NOT_FOUND              = 203
ERROR_FILENAME_EXCED_RANGE          = 206
ERROR_MORE_DATA                     = 234

WAIT_TIMEOUT                        = 258

ERROR_NO_MORE_ITEMS                 = 259
ERROR_PARTIAL_COPY                  = 299
ERROR_INVALID_ADDRESS               = 487
ERROR_THREAD_NOT_IN_PROCESS         = 566
ERROR_CONTROL_C_EXIT                = 572
ERROR_UNHANDLED_EXCEPTION           = 574
ERROR_ASSERTION_FAILURE             = 668
ERROR_WOW_ASSERTION                 = 670

ERROR_DBG_EXCEPTION_NOT_HANDLED     = 688
ERROR_DBG_REPLY_LATER               = 689
ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE  = 690
ERROR_DBG_TERMINATE_THREAD          = 691
ERROR_DBG_TERMINATE_PROCESS         = 692
ERROR_DBG_CONTROL_C                 = 693
ERROR_DBG_PRINTEXCEPTION_C          = 694
ERROR_DBG_RIPEXCEPTION              = 695
ERROR_DBG_CONTROL_BREAK             = 696
ERROR_DBG_COMMAND_EXCEPTION         = 697
ERROR_DBG_EXCEPTION_HANDLED         = 766
ERROR_DBG_CONTINUE                  = 767



#--- CONTEXT structures and constants -----------------------------------------
# The following values specify the type of access in the first parameter
# of the exception record when the exception code specifies an access
# violation.
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch

CONTEXT_i386                = 0x00010000    # this assumes that i386 and
CONTEXT_i486                = 0x00010000    # i486 have identical context records

CONTEXT_CONTROL             = (CONTEXT_i386 | 0x00000001) # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER             = (CONTEXT_i386 | 0x00000002) # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS            = (CONTEXT_i386 | 0x00000004) # DS, ES, FS, GS
CONTEXT_FLOATING_POINT      = (CONTEXT_i386 | 0x00000008) # 387 state
CONTEXT_DEBUG_REGISTERS     = (CONTEXT_i386 | 0x00000010) # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS  = (CONTEXT_i386 | 0x00000020) # cpu specific extensions

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                CONTEXT_EXTENDED_REGISTERS)

SIZE_OF_80387_REGISTERS     = 80
MAXIMUM_SUPPORTED_EXTENSION = 512



class STARTUPINFO(Structure):
    _fields_ = [
        ("cb",            DWORD),
        ("lpReserved",    LPTSTR),
        ("lpDesktop",     LPTSTR),
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
    ]


# When the dwDebugEventCode is evaluated
class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]


class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]


# Debug event structs
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]


# typedef struct _CREATE_THREAD_DEBUG_INFO {
#   HANDLE hThread;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
# } CREATE_THREAD_DEBUG_INFO;
class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('hThread',             HANDLE),
        ('lpThreadLocalBase',   LPVOID),
        ('lpStartAddress',      LPVOID),
    ]

# typedef struct _CREATE_PROCESS_DEBUG_INFO {
#   HANDLE hFile;
#   HANDLE hProcess;
#   HANDLE hThread;
#   LPVOID lpBaseOfImage;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } CREATE_PROCESS_DEBUG_INFO;
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('hProcess',                HANDLE),
        ('hThread',                 HANDLE),
        ('lpBaseOfImage',           LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpThreadLocalBase',       LPVOID),
        ('lpStartAddress',          LPVOID),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _EXIT_THREAD_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_THREAD_DEBUG_INFO;
class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _EXIT_PROCESS_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_PROCESS_DEBUG_INFO;
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _LOAD_DLL_DEBUG_INFO {
#   HANDLE hFile;
#   LPVOID lpBaseOfDll;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } LOAD_DLL_DEBUG_INFO;
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('lpBaseOfDll',             LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _UNLOAD_DLL_DEBUG_INFO {
#   LPVOID lpBaseOfDll;
# } UNLOAD_DLL_DEBUG_INFO;
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('lpBaseOfDll',         LPVOID),
    ]

# typedef struct _OUTPUT_DEBUG_STRING_INFO {
#   LPSTR lpDebugStringData;
#   WORD fUnicode;
#   WORD nDebugStringLength;
# } OUTPUT_DEBUG_STRING_INFO;
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ('lpDebugStringData',   LPVOID),    # don't use LPSTR
        ('fUnicode',            WORD),
        ('nDebugStringLength',  WORD),
    ]

# typedef struct _RIP_INFO {
#     DWORD dwError;
#     DWORD dwType;
# } RIP_INFO, *LPRIP_INFO;
class RIP_INFO(Structure):
    _fields_ = [
        ('dwError',             DWORD),
        ('dwType',              DWORD),
    ]


# it populates this union appropriately
class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
       ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
       ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
       ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
       ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
       ("LoadDll",           LOAD_DLL_DEBUG_INFO),
       ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
       ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
       ("RipInfo",           RIP_INFO),
        ]


# DEBUG_EVENT describes a debugging event
# that the debugger has trapped
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]


# Used by the CONTEXT structure
class FLOATING_SAVE_AREA(Structure):
    _fields_ = [

        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]


# The CONTEXT structure which holds all of the
# register values after a GetThreadContext() call
class CONTEXT_32(Structure):
    _fields_ = [

        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]


class CONTEXT(Structure):

    # This this bad and I feel bad
    def __str__(self):
        return "{}: {{{}}}".format(
                                   self.__class__.__name__,
                                   ", ".join(["{}: {}\n".format(  field[0],
                                                                hex(getattr(self,field[0])) if 
                                                                    type(getattr(self,field[0])) == int 
                                                                    else getattr(self,field[0])  

                                                             ) 
                                                            for field in self._fields_])
                                  )

    _pack_ = 1

    # Context Frame
    #
    #  This frame has a several purposes: 1) it is used as an argument to
    #  NtContinue, 2) is is used to constuct a call frame for APC delivery,
    #  and 3) it is used in the user level thread creation routines.
    #
    #  The layout of the record conforms to a standard call frame.

    _fields_ = [

        # The flags values within this flag control the contents of
        # a CONTEXT record.
        #
        # If the context record is used as an input parameter, then
        # for each portion of the context record controlled by a flag
        # whose value is set, it is assumed that that portion of the
        # context record contains valid context. If the context record
        # is being used to modify a threads context, then only that
        # portion of the threads context will be modified.
        #
        # If the context record is used as an IN OUT parameter to capture
        # the context of a thread, then only those portions of the thread's
        # context corresponding to set flags will be returned.
        #
        # The context record is never used as an OUT only parameter.

        ('ContextFlags',        DWORD),

        # This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
        # set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
        # included in CONTEXT_FULL.

        ('Dr0',                 DWORD),
        ('Dr1',                 DWORD),
        ('Dr2',                 DWORD),
        ('Dr3',                 DWORD),
        ('Dr6',                 DWORD),
        ('Dr7',                 DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_FLOATING_POINT.

        ('FloatSave',           FLOATING_SAVE_AREA),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_SEGMENTS.

        ('SegGs',               DWORD),
        ('SegFs',               DWORD),
        ('SegEs',               DWORD),
        ('SegDs',               DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_INTEGER.

        ('Edi',                 DWORD),
        ('Esi',                 DWORD),
        ('Ebx',                 DWORD),
        ('Edx',                 DWORD),
        ('Ecx',                 DWORD),
        ('Eax',                 DWORD),

        # This section is specified/returned if the
        # ContextFlags word contains the flag CONTEXT_CONTROL.

        ('Ebp',                 DWORD),
        ('Eip',                 DWORD),
        ('SegCs',               DWORD),         # MUST BE SANITIZED
        ('EFlags',              DWORD),         # MUST BE SANITIZED
        ('Esp',                 DWORD),
        ('SegSs',               DWORD),

        # This section is specified/returned if the ContextFlags word
        # contains the flag CONTEXT_EXTENDED_REGISTERS.
        # The format and contexts are processor specific.

        ('ExtendedRegisters',   BYTE * MAXIMUM_SUPPORTED_EXTENSION),
    ]

    _ctx_debug   = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7')
    _ctx_segs    = ('SegGs', 'SegFs', 'SegEs', 'SegDs', )
    _ctx_int     = ('Edi', 'Esi', 'Ebx', 'Edx', 'Ecx', 'Eax')
    _ctx_ctrl    = ('Ebp', 'Eip', 'SegCs', 'EFlags', 'Esp', 'SegSs')

  

PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT



class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]


class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class PROC_STRUCT(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
    ]


class SYSTEM_INFO_UNION(Union):
    _fields_ = [
        ("dwOemId", DWORD),
        ("sProcStruc", PROC_STRUCT),
    ]


class SYSTEM_INFO(Structure):
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class SYSTEMTIME(Structure):
    _pack_ = 1
    _fields_ = [
        ("wYear", WORD),
        ("wMonth", WORD),
        ("wDayOfWeek", WORD),
        ("wDay", WORD),
        ("wHour", WORD),
        ("wMinute", WORD),
        ("wSecond", WORD),
        ("wMilliseconds", WORD),
    ]


class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_ushort),
        ("MaximumLength", c_ushort),
        ("Buffer", c_wchar_p),
    ]



# typedef struct _MODULEINFO {
#   LPVOID lpBaseOfDll;
#   DWORD  SizeOfImage;
#   LPVOID EntryPoint;
# } MODULEINFO, *LPMODULEINFO;
class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll",     LPVOID),    # remote pointer
        ("SizeOfImage",     DWORD),
        ("EntryPoint",      LPVOID),    # remote pointer
]
LPMODULEINFO = POINTER(MODULEINFO)




# typedef struct tagMODULEENTRY32 {
#   DWORD dwSize;
#   DWORD th32ModuleID;
#   DWORD th32ProcessID;
#   DWORD GlblcntUsage;
#   DWORD ProccntUsage;
#   BYTE* modBaseAddr;
#   DWORD modBaseSize;
#   HMODULE hModule;
#   TCHAR szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR szExePath[MAX_PATH];
# } MODULEENTRY32,  *PMODULEENTRY32;
class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   LPVOID),  # BYTE*
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]
LPMODULEENTRY32 = POINTER(MODULEENTRY32)






