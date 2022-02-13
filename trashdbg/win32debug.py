##
## Copy-pasta directly from WinAppDebug so we don't have to implement ourselves
## https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/util.py
##

import ctypes
import win32types

class DebugRegister (object):
    """
    Class to manipulate debug registers.
    Used by L{HardwareBreakpoint}.
    @group bp_type flags used by HardwareBreakpoint:
        BREAK_ON_EXECUTION, BREAK_ON_WRITE, BREAK_ON_ACCESS, BREAK_ON_IO_ACCESS
    @group Size flags used by HardwareBreakpoint:
        WATCH_BYTE, WATCH_WORD, WATCH_DWORD, WATCH_QWORD
    @group Bitwise masks for Dr7:
        enableMask, disableMask, triggerMask, watchMask, clearMask,
        generalDetectMask
    @group Bitwise masks for Dr6:
        hitMask, hitMaskAll, debugAccessMask, singleStepMask, taskSwitchMask,
        clearDr6Mask, clearHitMask
    @group Debug control MSR definitions:
        DebugCtlMSR, LastBranchRecord, BranchTrapFlag, PinControl,
        LastBranchToIP, LastBranchFromIP,
        LastExceptionToIP, LastExceptionFromIP
    @type BREAK_ON_EXECUTION: int
    @cvar BREAK_ON_EXECUTION: Break on execution.
    @type BREAK_ON_WRITE: int
    @cvar BREAK_ON_WRITE: Break on write.
    @type BREAK_ON_ACCESS: int
    @cvar BREAK_ON_ACCESS: Break on read or write.
    @type BREAK_ON_IO_ACCESS: int
    @cvar BREAK_ON_IO_ACCESS: Break on I/O port access.
        Not supported by any hardware.
    @type WATCH_BYTE: int
    @cvar WATCH_BYTE: Watch a byte.
    @type WATCH_WORD: int
    @cvar WATCH_WORD: Watch a word.
    @type WATCH_DWORD: int
    @cvar WATCH_DWORD: Watch a double word.
    @type WATCH_QWORD: int
    @cvar WATCH_QWORD: Watch one quad word.
    @type enableMask: 4-tuple of integers
    @cvar enableMask:
        Enable bit on C{Dr7} for each slot.
        Works as a bitwise-OR mask.
    @type disableMask: 4-tuple of integers
    @cvar disableMask:
        Mask of the enable bit on C{Dr7} for each slot.
        Works as a bitwise-AND mask.
    @type triggerMask: 4-tuple of 2-tuples of integers
    @cvar triggerMask:
        Trigger bits on C{Dr7} for each trigger flag value.
        Each 2-tuple has the bitwise-OR mask and the bitwise-AND mask.
    @type watchMask: 4-tuple of 2-tuples of integers
    @cvar watchMask:
        Watch bits on C{Dr7} for each watch flag value.
        Each 2-tuple has the bitwise-OR mask and the bitwise-AND mask.
    @type clearMask: 4-tuple of integers
    @cvar clearMask:
        Mask of all important bits on C{Dr7} for each slot.
        Works as a bitwise-AND mask.
    @type generalDetectMask: integer
    @cvar generalDetectMask:
        General detect mode bit. It enables the processor to notify the
        debugger when the debugee is trying to access one of the debug
        registers.
    @type hitMask: 4-tuple of integers
    @cvar hitMask:
        Hit bit on C{Dr6} for each slot.
        Works as a bitwise-AND mask.
    @type hitMaskAll: integer
    @cvar hitMaskAll:
        Bitmask for all hit bits in C{Dr6}. Useful to know if at least one
        hardware breakpoint was hit, or to clear the hit bits only.
    @type clearHitMask: integer
    @cvar clearHitMask:
        Bitmask to clear all the hit bits in C{Dr6}.
    @type debugAccessMask: integer
    @cvar debugAccessMask:
        The debugee tried to access a debug register. Needs bit
        L{generalDetectMask} enabled in C{Dr7}.
    @type singleStepMask: integer
    @cvar singleStepMask:
        A single step exception was raised. Needs the trap flag enabled.
    @type taskSwitchMask: integer
    @cvar taskSwitchMask:
        A task switch has occurred. Needs the TSS T-bit set to 1.
    @type clearDr6Mask: integer
    @cvar clearDr6Mask:
        Bitmask to clear all meaningful bits in C{Dr6}.
    """

    BREAK_ON_EXECUTION  = 0
    BREAK_ON_WRITE      = 1
    BREAK_ON_ACCESS     = 3
    BREAK_ON_IO_ACCESS  = 2

    WATCH_BYTE  = 0
    WATCH_WORD  = 1
    WATCH_DWORD = 3
    WATCH_QWORD = 2

    try:
        registerMask = win32types.SIZE_T(-1).value
    except TypeError as e:
        if ctypes.sizeof(win32types.SIZE_T) == 4:
            registerMask = 0xFFFFFFFF
        elif ctypes.sizeof(win32types.SIZE_T) == 8:
            registerMask = 0xFFFFFFFFFFFFFFFF
        else:
            raise

#------------------------------------------------------------------------------

    ###########################################################################
    # http://en.wikipedia.org/wiki/Debug_register
    #
    # DR7 - Debug control
    #
    # The low-order eight bits of DR7 (0,2,4,6 and 1,3,5,7) selectively enable
    # the four address breakpoint conditions. There are two levels of enabling:
    # the local (0,2,4,6) and global (1,3,5,7) levels. The local enable bits
    # are automatically reset by the processor at every task switch to avoid
    # unwanted breakpoint conditions in the new task. The global enable bits
    # are not reset by a task switch; therefore, they can be used for
    # conditions that are global to all tasks.
    #
    # Bits 16-17 (DR0), 20-21 (DR1), 24-25 (DR2), 28-29 (DR3), define when
    # breakpoints trigger. Each breakpoint has a two-bit entry that specifies
    # whether they break on execution (00b), data write (01b), data read or
    # write (11b). 10b is defined to mean break on IO read or write but no
    # hardware supports it. Bits 18-19 (DR0), 22-23 (DR1), 26-27 (DR2), 30-31
    # (DR3), define how large area of memory is watched by breakpoints. Again
    # each breakpoint has a two-bit entry that specifies whether they watch
    # one (00b), two (01b), eight (10b) or four (11b) bytes.
    ###########################################################################

    # Dr7 |= enableMask[register_index]
    enableMask = (
        1 << 0,     # Dr0 (bit 0)
        1 << 2,     # Dr1 (bit 2)
        1 << 4,     # Dr2 (bit 4)
        1 << 6,     # Dr3 (bit 6)
    )

    # Dr7 &= disableMask[register_index]
    disableMask = []
    for x in enableMask:
        disableMask.append(registerMask ^ x)
    disableMask = tuple(disableMask)
    del x

    # orMask, andMask = triggerMask[register_index][bp_type]
    # Dr7 = (Dr7 & andMask) | orMask    # to set
    # Dr7 = Dr7 & andMask               # to remove
    triggerMask = (
        # Dr0 (bits 16-17)
        (
            ((0 << 16), (3 << 16) ^ registerMask),  # execute
            ((1 << 16), (3 << 16) ^ registerMask),  # write
            ((2 << 16), (3 << 16) ^ registerMask),  # io read
            ((3 << 16), (3 << 16) ^ registerMask),  # access
        ),
        # Dr1 (bits 20-21)
        (
            ((0 << 20), (3 << 20) ^ registerMask),  # execute
            ((1 << 20), (3 << 20) ^ registerMask),  # write
            ((2 << 20), (3 << 20) ^ registerMask),  # io read
            ((3 << 20), (3 << 20) ^ registerMask),  # access
        ),
        # Dr2 (bits 24-25)
        (
            ((0 << 24), (3 << 24) ^ registerMask),  # execute
            ((1 << 24), (3 << 24) ^ registerMask),  # write
            ((2 << 24), (3 << 24) ^ registerMask),  # io read
            ((3 << 24), (3 << 24) ^ registerMask),  # access
        ),
        # Dr3 (bits 28-29)
        (
            ((0 << 28), (3 << 28) ^ registerMask),  # execute
            ((1 << 28), (3 << 28) ^ registerMask),  # write
            ((2 << 28), (3 << 28) ^ registerMask),  # io read
            ((3 << 28), (3 << 28) ^ registerMask),  # access
        ),
    )

    # orMask, andMask = watchMask[register][watch]
    # Dr7 = (Dr7 & andMask) | orMask    # to set
    # Dr7 = Dr7 & andMask               # to remove
    watchMask = (
        # Dr0 (bits 18-19)
        (
            ((0 << 18), (3 << 18) ^ registerMask),  # byte
            ((1 << 18), (3 << 18) ^ registerMask),  # word
            ((2 << 18), (3 << 18) ^ registerMask),  # qword
            ((3 << 18), (3 << 18) ^ registerMask),  # dword
        ),
        # Dr1 (bits 22-23)
        (
            ((0 << 23), (3 << 23) ^ registerMask),  # byte
            ((1 << 23), (3 << 23) ^ registerMask),  # word
            ((2 << 23), (3 << 23) ^ registerMask),  # qword
            ((3 << 23), (3 << 23) ^ registerMask),  # dword
        ),
        # Dr2 (bits 26-27)
        (
            ((0 << 26), (3 << 26) ^ registerMask),  # byte
            ((1 << 26), (3 << 26) ^ registerMask),  # word
            ((2 << 26), (3 << 26) ^ registerMask),  # qword
            ((3 << 26), (3 << 26) ^ registerMask),  # dword
        ),
        # Dr3 (bits 30-31)
        (
            ((0 << 30), (3 << 31) ^ registerMask),  # byte
            ((1 << 30), (3 << 31) ^ registerMask),  # word
            ((2 << 30), (3 << 31) ^ registerMask),  # qword
            ((3 << 30), (3 << 31) ^ registerMask),  # dword
        ),
    )

    # Dr7 = Dr7 & clearMask[register]
    clearMask = (
        registerMask ^ ( (1 << 0) + (3 << 16) + (3 << 18) ),    # Dr0
        registerMask ^ ( (1 << 2) + (3 << 20) + (3 << 22) ),    # Dr1
        registerMask ^ ( (1 << 4) + (3 << 24) + (3 << 26) ),    # Dr2
        registerMask ^ ( (1 << 6) + (3 << 28) + (3 << 30) ),    # Dr3
    )

    # Dr7 = Dr7 | generalDetectMask
    generalDetectMask = (1 << 13)

    ###########################################################################
    # http://en.wikipedia.org/wiki/Debug_register
    #
    # DR6 - Debug status
    #
    # The debug status register permits the debugger to determine which debug
    # conditions have occurred. When the processor detects an enabled debug
    # exception, it sets the low-order bits of this register (0,1,2,3) before
    # entering the debug exception handler.
    #
    # Note that the bits of DR6 are never cleared by the processor. To avoid
    # any confusion in identifying the next debug exception, the debug handler
    # should move zeros to DR6 immediately before returning.
    ###########################################################################

    # bool(Dr6 & hitMask[register])
    hitMask = (
        (1 << 0),   # Dr0
        (1 << 1),   # Dr1
        (1 << 2),   # Dr2
        (1 << 3),   # Dr3
    )

    # bool(Dr6 & anyHitMask)
    hitMaskAll = hitMask[0] | hitMask[1] | hitMask[2] | hitMask[3]

    # Dr6 = Dr6 & clearHitMask
    clearHitMask = registerMask ^ hitMaskAll

    # bool(Dr6 & debugAccessMask)
    debugAccessMask = (1 << 13)

    # bool(Dr6 & singleStepMask)
    singleStepMask  = (1 << 14)

    # bool(Dr6 & taskSwitchMask)
    taskSwitchMask  = (1 << 15)

    # Dr6 = Dr6 & clearDr6Mask
    clearDr6Mask = registerMask ^ (hitMaskAll | \
                            debugAccessMask | singleStepMask | taskSwitchMask)

#------------------------------------------------------------------------------

###############################################################################
#
#    (from the AMD64 manuals)
#
#    The fields within the DebugCtlMSR register are:
#
#    Last-Branch Record (LBR) - Bit 0, read/write. Software sets this bit to 1
#    to cause the processor to record the source and target addresses of the
#    last control transfer taken before a debug exception occurs. The recorded
#    control transfers include branch instructions, interrupts, and exceptions.
#
#    Branch Single Step (BTF) - Bit 1, read/write. Software uses this bit to
#    change the behavior of the rFLAGS.TF bit. When this bit is cleared to 0,
#    the rFLAGS.TF bit controls instruction single stepping, (normal behavior).
#    When this bit is set to 1, the rFLAGS.TF bit controls single stepping on
#    control transfers. The single-stepped control transfers include branch
#    instructions, interrupts, and exceptions. Control-transfer single stepping
#    requires both BTF=1 and rFLAGS.TF=1.
#
#    Performance-Monitoring/Breakpoint Pin-Control (PBi) - Bits 5-2, read/write.
#    Software uses these bits to control the type of information reported by
#    the four external performance-monitoring/breakpoint pins on the processor.
#    When a PBi bit is cleared to 0, the corresponding external pin (BPi)
#    reports performance-monitor information. When a PBi bit is set to 1, the
#    corresponding external pin (BPi) reports breakpoint information.
#
#    All remaining bits in the DebugCtlMSR register are reserved.
#
#    Software can enable control-transfer single stepping by setting
#    DebugCtlMSR.BTF to 1 and rFLAGS.TF to 1. The processor automatically
#    disables control-transfer single stepping when a debug exception (#DB)
#    occurs by clearing DebugCtlMSR.BTF to 0. rFLAGS.TF is also cleared when a
#    #DB exception occurs. Before exiting the debug-exception handler, software
#    must set both DebugCtlMSR.BTF and rFLAGS.TF to 1 to restart single
#    stepping.
#
###############################################################################

    DebugCtlMSR      = 0x1D9
    LastBranchRecord = (1 << 0)
    BranchTrapFlag   = (1 << 1)
    PinControl       = (
                        (1 << 2),   # PB1
                        (1 << 3),   # PB2
                        (1 << 4),   # PB3
                        (1 << 5),   # PB4
                       )

###############################################################################
#
#    (from the AMD64 manuals)
#
#    Control-transfer recording MSRs: LastBranchToIP, LastBranchFromIP,
#    LastExceptionToIP, and LastExceptionFromIP. These registers are loaded
#    automatically by the processor when the DebugCtlMSR.LBR bit is set to 1.
#    These MSRs are read-only.
#
#    The processor automatically disables control-transfer recording when a
#    debug exception (#DB) occurs by clearing DebugCtlMSR.LBR to 0. The
#    contents of the control-transfer recording MSRs are not altered by the
#    processor when the #DB occurs. Before exiting the debug-exception handler,
#    software can set DebugCtlMSR.LBR to 1 to re-enable the recording mechanism.
#
###############################################################################

    LastBranchToIP      = 0x1DC
    LastBranchFromIP    = 0x1DB
    LastExceptionToIP   = 0x1DE
    LastExceptionFromIP = 0x1DD

#------------------------------------------------------------------------------

    @classmethod
    def clear_bp(self, ctx, register_index):
        """
        Clears a hardware breakpoint.
        @see: find_slot, set_bp
        @type  ctx: dict( str S{->} int )
        @param ctx: Thread context dictionary.
        @type  register_index: int
        @param register_index: Slot (debug register) for hardware breakpoint.
        """
        ctx.Dr7 &= self.clearMask[register_index]
        setattr(ctx, 'Dr%d' % register_index, 0)

    @classmethod
    def set_bp(self, ctx, register_index, bp_address, bp_type, bp_size):
        """
        Sets a hardware breakpoint.
        @see: clear_bp, find_slot
        @type  ctx: dict( str S{->} int )
        @param ctx: Thread context dictionary.
        @type  register_index: int
        @param register_index: Slot (debug register_index).
        @type  bp_address: int
        @param bp_address: Memory bp_address.
        @type  bp_type: int
        @param bp_type: bp_type flag. See L{HardwareBreakpoint.validTriggers}.
        @type  bp_size: int
        @param bp_size: Watch flag. See L{HardwareBreakpoint.validWatchSizes}.
        """
        Dr7 = ctx.Dr7
        Dr7 |= self.enableMask[register_index]
        orMask, andMask = self.triggerMask[register_index][bp_type]
        Dr7 &= andMask
        Dr7 |= orMask
        orMask, andMask = self.watchMask[register_index][bp_size]
        Dr7 &= andMask
        Dr7 |= orMask
        ctx.Dr7 = Dr7
        setattr(ctx, 'Dr%d' % register_index, bp_address)

    @classmethod
    def find_slot(self, ctx):
        """
        Finds an empty slot to set a hardware breakpoint.
        @see: clear_bp, set_bp
        @type  ctx: dict( str S{->} int )
        @param ctx: Thread context dictionary.
        @rtype:  int
        @return: Slot (debug register_index) for hardware breakpoint.
        """
        Dr7  = ctx['Dr7']
        slot = 0
        for m in self.enableMask:
            if (Dr7 & m) == 0:
                return slot
            slot += 1
        return None


BREAK_ON_EXECUTION  = DebugRegister.BREAK_ON_EXECUTION
BREAK_ON_WRITE      = DebugRegister.BREAK_ON_WRITE
BREAK_ON_ACCESS     = DebugRegister.BREAK_ON_ACCESS

WATCH_BYTE  = DebugRegister.WATCH_BYTE
WATCH_WORD  = DebugRegister.WATCH_WORD
WATCH_DWORD = DebugRegister.WATCH_DWORD
WATCH_QWORD = DebugRegister.WATCH_QWORD

validTriggers = (
    BREAK_ON_EXECUTION,
    BREAK_ON_WRITE,
    BREAK_ON_ACCESS,
)

validWatchSizes = (
    WATCH_BYTE,
    WATCH_WORD,
    WATCH_DWORD,
    WATCH_QWORD,
)
