"""
Cortex-M0+ cycle estimator for the TI MSPM0L2228
=================================================

Estimates how many CPU clock cycles a sequence of *executed* instructions
takes, for use when computing how long to wait after a trigger before
injecting a fault.

Sources
-------
- ARM DDI 0484C  - Cortex-M0+ TRM, Table 3-1 "Cortex-M0+ instruction summary".
                   These are the base (zero-wait-state) per-instruction costs.
- TI SLASF94A    - MSPM0L2228 datasheet:
    * §8.2  CPU: "ARMv6-M Thumb instruction set (little endian) with
           **single-cycle 32x32 multiply instruction**",
           "Single-cycle access to GPIO registers through Arm single-cycle
           IO port",
           "**Pre-fetch logic** to improve sequential code execution, and
           **I-cache with four 64-bit cache lines**".
    * §7.3  Recommended operating conditions:
           f_MCLK with 1 flash wait state  -> MAX 32 MHz
           f_MCLK with 0 flash wait states -> MAX 24 MHz
           (wait states are managed automatically by SYSCTL)
    * §8.11 SRAM: "zero wait state access across the supported CPU frequency
           range of the device".

Model
-----
Per-instruction base costs come from TRM Table 3-1, adjusted for what the
MSPM0L2228 actually implements:

* MULS costs **1 cycle** (the device has the single-cycle multiplier).  The
  32-cycle variant documented in the TRM does not apply to this part.
* LDR/STR cost 2 cycles normally, or 1 cycle when they target the Arm
  single-cycle I/O port (e.g. GPIO).  Since the target address is not known
  at static-analysis time we keep the lower bound at 1 and the best/upper
  bound at 2.
* LDM/STM/PUSH/POP cost 1 + N, where N is the number of registers in the
  list.  POP {..., PC} costs 3 + N.

Flash / I-cache
---------------
At 32 MHz the flash needs 1 wait state.  The core's pre-fetch logic hides
this for sequential code, so no per-instruction stall is charged for a
straight-line stream.  The I-cache (4 lines x 64 bits = 32 bytes, modelled
as fully-associative LRU) is simulated over the executed trace: when control
flow arrives at an address that is *not* the fall-through of the previous
instruction (a taken branch, call, return, POP/LDR-to-PC, ...) and the
target's cache line is not resident, a flash fetch stall is charged.

Bounds for a fetch miss:
    lower = 0            (target happened to be prefetched / in the pipeline)
    best  = wait_states  (the exposed flash wait state, 1 at 32 MHz)
    upper = wait_states

The cache is warmed for one pass before stalls are counted by default
(``warm_cache=True``), which matches the glitch scenario: the trigger is
usually called once per loop iteration, so the code after it has already
executed and is resident in the I-cache.

Limitations
-----------
* The exact MSPM0 I-cache replacement policy / prefetch depth is not in the
  datasheet (it is in the MSPM0 L-Series TRM).  A fully-associative LRU cache
  is used as a reasonable approximation.
* AHB peripheral latency beyond the documented 2-cycle base is not modelled.
* Interrupt/exception entry latency (~15 cycles of hardware stacking) and
  WFI/WFE wait time are excluded; they are system dependent.
"""

from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
import re
from typing import Optional

from capstone import CsInsn
from capstone.arm_const import (
    ARM_INS_LDM, ARM_INS_STM, ARM_INS_PUSH, ARM_INS_POP,
    ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRH, ARM_INS_LDRSB, ARM_INS_LDRSH,
    ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH,
    ARM_INS_B, ARM_INS_BL, ARM_INS_BX, ARM_INS_BLX,
    ARM_INS_CBZ, ARM_INS_CBNZ,
    ARM_INS_MUL,
    ARM_INS_MOV, ARM_INS_ADD,
    ARM_INS_ISB, ARM_INS_DSB, ARM_INS_DMB,
    ARM_INS_WFI, ARM_INS_WFE, ARM_INS_SEV, ARM_INS_YIELD,
    ARM_INS_MRS, ARM_INS_MSR, ARM_INS_CPS,
    ARM_INS_SVC, ARM_INS_BKPT,
    ARM_INS_NOP,
    ARM_OP_REG,
    ARM_REG_PC,
)

# ─────────────────────────────────────────────────────────────────────────────
# Device constants (TI MSPM0L2228)
# ─────────────────────────────────────────────────────────────────────────────

CLOCK_HZ = 32_000_000  # 32 MHz (datasheet §7.3 / §7.10.1)

FLASH_BASE = 0x0000_0000
FLASH_END  = 0x0003_FFFF  # 256 KB main flash

SRAM_BASE  = 0x2000_0000
SRAM_END   = 0x2007_FFFF  # 32 KB SRAM

# Flash wait states at 32 MHz (datasheet §7.3)
FLASH_WAIT_STATES = 1

# Instruction cache: four 64-bit lines (datasheet §8.2)
ICACHE_LINES = 4
ICACHE_LINE_BYTES = 8

_LOADS = (
    ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRH, ARM_INS_LDRSB, ARM_INS_LDRSH,
)
_STORES = (ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH)
_BARRIERS = (ARM_INS_ISB, ARM_INS_DSB, ARM_INS_DMB)
_HINTS_2 = (ARM_INS_WFI, ARM_INS_WFE)


# ─────────────────────────────────────────────────────────────────────────────
# Device configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DeviceConfig:
    """Tunable device parameters.  Defaults describe the MSPM0L2228."""
    clock_hz: int = CLOCK_HZ
    flash_wait_states: int = FLASH_WAIT_STATES
    icache_lines: int = ICACHE_LINES
    icache_line_bytes: int = ICACHE_LINE_BYTES
    # The MSPM0L2228 has a single-cycle 32x32 multiplier (datasheet §8.2).
    single_cycle_multiply: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Result type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CycleEstimate:
    """
    Cycle-count estimate with lower and upper bounds.

    lower  - minimum plausible cycles (best case: loads/stores hit the
             single-cycle I/O port, every branch target was already
             prefetched).
    best   - most-likely cycles (loads/stores to AHB/SRAM, single-cycle MUL,
             branch targets that miss the I-cache pay the flash wait state).
    upper  - maximum plausible cycles (same as best for deterministic
             instructions; WFI/WFE/SVC have unbounded real costs that are
             excluded here).
    """
    lower: int
    best:  int
    upper: int

    def __str__(self) -> str:
        return f"CycleEstimate(lower={self.lower}, best={self.best}, upper={self.upper})"

    def to_microseconds(self, clock_hz: int = CLOCK_HZ) -> tuple[float, float, float]:
        """Return (lower_us, best_us, upper_us)."""
        s = 1e6 / clock_hz
        return self.lower * s, self.best * s, self.upper * s


# ─────────────────────────────────────────────────────────────────────────────
# Instruction decoding helpers
# ─────────────────────────────────────────────────────────────────────────────

_REGISTER_RE = re.compile(r'^(?:r(?:1[0-5]|[0-9])|sp|lr|pc|fp|ip|sl|sb)$')
_RANGE_RE = re.compile(r'^r(\d{1,2})\s*-\s*r(\d{1,2})$')


def _is_flash(addr: int) -> bool:
    return FLASH_BASE <= addr <= FLASH_END


def _list_count(insn: CsInsn) -> int:
    """
    Number of registers in a brace-enclosed register list, e.g. the N in
    ``ldm r0!, {r1, r2, r3}`` or ``push {r4, lr}``.

    Parses ``op_str`` (works whether or not Capstone was opened with
    ``detail=True``), expands ``rX-rY`` ranges, and ignores the base register
    that LDM/STM place outside the braces.
    """
    m = re.search(r'\{([^}]*)\}', insn.op_str.lower())
    if not m:
        return 0
    count = 0
    for token in m.group(1).split(','):
        token = token.strip()
        if not token:
            continue
        rng = _RANGE_RE.match(token)
        if rng:
            lo, hi = int(rng.group(1)), int(rng.group(2))
            if hi >= lo:
                count += hi - lo + 1
        elif _REGISTER_RE.match(token):
            count += 1
    return count


def _has_pc(insn: CsInsn) -> bool:
    """True if PC (R15) appears in the register operands / op_str."""
    try:
        for op in insn.operands:
            if op.type == ARM_OP_REG and op.reg == ARM_REG_PC:
                return True
        return False
    except Exception:
        return bool(re.search(r'\bpc\b', insn.op_str.lower()))


def _dest_is_pc(insn: CsInsn) -> bool:
    """True if the destination (first operand) is PC, e.g. ``mov pc, r0``."""
    first = insn.op_str.split(',')[0].strip().lower()
    return first == "pc"


def _taken(insn: CsInsn, next_insn: Optional[CsInsn]) -> bool:
    """
    Whether a conditional branch is taken, inferred from the executed trace:
    the branch is taken when the next executed instruction is not the
    fall-through.  When there is no next instruction the branch kind decides
    (unconditional transfers are always taken).
    """
    if next_insn is not None:
        return next_insn.address != insn.address + insn.size
    if insn.id in (ARM_INS_BL, ARM_INS_BX, ARM_INS_BLX):
        return True
    if insn.id == ARM_INS_B and insn.mnemonic == "b":
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-instruction base costs (zero wait states)
# ─────────────────────────────────────────────────────────────────────────────

def _insn_bounds(
    insn: CsInsn,
    next_insn: Optional[CsInsn],
    device: DeviceConfig,
) -> tuple[int, int, int]:
    """
    Return (lower, best, upper) zero-wait-state base cycle counts for one
    instruction, per TRM Table 3-1 with MSPM0L2228 corrections.
    """
    iid = insn.id

    # ── Branches ──────────────────────────────────────────────────────────
    if iid == ARM_INS_BL:
        return 3, 3, 3
    if iid in (ARM_INS_BX, ARM_INS_BLX):
        return 2, 2, 2
    if iid == ARM_INS_B:
        if insn.mnemonic == "b":            # unconditional
            return 2, 2, 2
        c = 2 if _taken(insn, next_insn) else 1   # conditional B<cc>
        return c, c, c
    # CBZ/CBNZ are not part of ARMv6-M (Cortex-M0+); kept defensively.
    if iid in (ARM_INS_CBZ, ARM_INS_CBNZ):
        c = 2 if _taken(insn, next_insn) else 1
        return c, c, c

    # ── Stack ─────────────────────────────────────────────────────────────
    if iid == ARM_INS_PUSH:
        n = max(_list_count(insn), 1)
        c = 1 + n
        return c, c, c
    if iid == ARM_INS_POP:
        n = max(_list_count(insn), 1)
        c = (3 + n) if _has_pc(insn) else (1 + n)
        return c, c, c

    # ── Load/store multiple ───────────────────────────────────────────────
    if iid in (ARM_INS_LDM, ARM_INS_STM):
        n = max(_list_count(insn), 1)
        c = 1 + n
        return c, c, c

    # ── Single loads / stores ─────────────────────────────────────────────
    # 2 cycles to AHB/SRAM, 1 cycle to the single-cycle I/O port.
    if iid in _LOADS or iid in _STORES:
        return 1, 2, 2

    # ── Multiply ──────────────────────────────────────────────────────────
    if iid == ARM_INS_MUL:
        if device.single_cycle_multiply:
            return 1, 1, 1          # MSPM0L2228: single-cycle 32x32
        return 1, 32, 32            # low-area variant

    # ── Barriers / special registers ──────────────────────────────────────
    if iid in _BARRIERS:
        return 3, 3, 3
    if iid in (ARM_INS_MRS, ARM_INS_MSR):
        return 3, 3, 3

    # ── Hints ─────────────────────────────────────────────────────────────
    if iid in _HINTS_2:
        # Instruction-only cost; actual wait time is unbounded and excluded.
        return 2, 2, 2
    if iid in (ARM_INS_SEV, ARM_INS_YIELD, ARM_INS_CPS):
        return 1, 1, 1
    if iid == ARM_INS_NOP:
        return 1, 1, 1

    # ── Exception entry (instruction-only; stacking excluded) ─────────────
    if iid == ARM_INS_SVC:
        return 2, 2, 2
    if iid == ARM_INS_BKPT:
        return 1, 1, 1

    # ── Writes to PC ──────────────────────────────────────────────────────
    if iid in (ARM_INS_MOV, ARM_INS_ADD) and _dest_is_pc(insn):
        return 2, 2, 2

    # ── Default 1-cycle ALU ───────────────────────────────────────────────
    return 1, 1, 1


# ─────────────────────────────────────────────────────────────────────────────
# I-cache model
# ─────────────────────────────────────────────────────────────────────────────

class _ICache:
    """Tiny fully-associative LRU instruction cache."""

    def __init__(self, lines: int, line_bytes: int):
        self.lines = max(lines, 1)
        self.line_bytes = max(line_bytes, 1)
        self._entries: "OrderedDict[int, None]" = OrderedDict()

    def _line(self, addr: int) -> int:
        return addr // self.line_bytes

    def contains(self, addr: int) -> bool:
        return self._line(addr) in self._entries

    def touch(self, addr: int) -> None:
        line = self._line(addr)
        if line in self._entries:
            self._entries.move_to_end(line)
        else:
            self._entries[line] = None
            if len(self._entries) > self.lines:
                self._entries.popitem(last=False)


def _arrived_via_transfer(prev_end: Optional[int], addr: int) -> bool:
    return prev_end is not None and addr != prev_end


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def estimate_cycles(
    instructions: list[CsInsn],
    *,
    device: DeviceConfig = DeviceConfig(),
    warm_cache: bool = True,
    verbose: bool = False,
) -> CycleEstimate:
    """
    Estimate lower, best, and upper cycle counts for an executed instruction
    trace on the TI MSPM0L2228 (32 MHz, 1 flash wait state, 4x64-bit I-cache).

    Parameters
    ----------
    instructions : list[CsInsn]
        Ordered list of *executed* instructions (execution order, not binary
        order) as returned by Capstone.
    device : DeviceConfig
        Device timing parameters.  Defaults to the MSPM0L2228.
    warm_cache : bool
        If True (default) the I-cache is warmed with one pass over the trace
        before stalls are counted.  This models the usual glitch scenario
        where the trigger (and therefore the code after it) has already run.
    verbose : bool
        Print a per-instruction breakdown when True.

    Returns
    -------
    CycleEstimate
        .lower  - best case (single-cycle I/O accesses, all branch targets
                  prefetched/cached)
        .best   - most likely (AHB/SRAM accesses, single-cycle MUL, I-cache
                  misses pay the flash wait state)
        .upper  - worst case for the modelled effects (WFI/WFE/SVC real wait
                  time excluded as it is unbounded / system dependent)
    """
    total_lo = total_best = total_hi = 0

    if not instructions:
        return CycleEstimate(0, 0, 0)

    cache = _ICache(device.icache_lines, device.icache_line_bytes)

    # Warm the I-cache so steady-state hits are credited (one extra pass).
    if warm_cache:
        for insn in instructions:
            cache.touch(insn.address)

    if verbose:
        print(f"  {'Address':10}  {'Mnemonic':8}  {'Operands':26}  "
              f"{'lo':>4}  {'best':>4}  {'hi':>4}  Notes")
        print("  " + "-" * 82)

    prev_end: Optional[int] = None
    for i, insn in enumerate(instructions):
        next_insn = instructions[i + 1] if i + 1 < len(instructions) else None

        # 1. Zero-wait-state base bounds from TRM Table 3-1.
        lo, best, hi = _insn_bounds(insn, next_insn, device)

        # 2. Flash fetch stall on an I-cache miss at a control-flow target.
        notes = []
        miss = False
        if (
            _is_flash(insn.address)
            and _arrived_via_transfer(prev_end, insn.address)
            and not cache.contains(insn.address)
        ):
            miss = True
            best += device.flash_wait_states
            hi += device.flash_wait_states
            notes.append(f"icache miss (+{device.flash_wait_states})")

        cache.touch(insn.address)
        prev_end = insn.address + insn.size

        if verbose:
            note_str = ", ".join(notes)
            print(f"  0x{insn.address:08x}  {insn.mnemonic:<8}  {insn.op_str:<26}  "
                  f"{lo:4d}  {best:4d}  {hi:4d}  {note_str}")

        total_lo += lo
        total_best += best
        total_hi += hi

    return CycleEstimate(lower=total_lo, best=total_best, upper=total_hi)


def cycles_to_microseconds(cycles: int, clock_hz: int = CLOCK_HZ) -> float:
    """Convert a cycle count to microseconds."""
    return cycles / clock_hz * 1e6


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import types

    def _mock(iid, addr, mnemonic, op_str="", size=2, operands=None):
        ins = types.SimpleNamespace()
        ins.id, ins.address = iid, addr
        ins.mnemonic, ins.op_str = mnemonic, op_str
        ins.size = size
        # Only expose .operands when explicitly supplied.  This mirrors the
        # engine, which opens Capstone without detail=True so accessing
        # .operands raises and the op_str fallbacks are used.
        if operands is not None:
            ins.operands = operands
        return ins

    def _base(iid, addr, mnemonic, op_str="", size=2, next_addr=None):
        ins = _mock(iid, addr, mnemonic, op_str, size)
        nxt = None if next_addr is None else _mock(0, next_addr, "nop")
        return _insn_bounds(ins, nxt, DeviceConfig())

    print("Base per-instruction costs (zero wait states):")
    checks = [
        ("movs r0, #0",        _base(1,   0, "movs", "r0, #0"),            (1, 1, 1)),
        ("muls r0, r1, r0",    _base(ARM_INS_MUL, 0, "muls", "r0, r1, r0"), (1, 1, 1)),
        ("ldr r2, [r0, #4]",   _base(ARM_INS_LDR, 0, "ldr", "r2, [r0, #4]"), (1, 2, 2)),
        ("str r2, [r1, #0]",   _base(ARM_INS_STR, 0, "str", "r2, [r1, #0]"), (1, 2, 2)),
        ("push {r4, lr}",      _base(ARM_INS_PUSH, 0, "push", "{r4, lr}"),   (3, 3, 3)),
        ("pop {r4, pc}",       _base(ARM_INS_POP, 0, "pop", "{r4, pc}"),     (5, 5, 5)),
        ("pop {r4, r5}",       _base(ARM_INS_POP, 0, "pop", "{r4, r5}"),     (3, 3, 3)),
        ("ldm r0!, {r1,r2,r3}", _base(ARM_INS_LDM, 0, "ldm", "r0!, {r1, r2, r3}"), (4, 4, 4)),
        ("stm r0!, {r1,r2}",   _base(ARM_INS_STM, 0, "stm", "r0!, {r1, r2}"), (3, 3, 3)),
        ("bl",                 _base(ARM_INS_BL, 0, "bl", "foo"),            (3, 3, 3)),
        ("bx lr",              _base(ARM_INS_BX, 0, "bx", "lr"),             (2, 2, 2)),
        ("b (uncond)",         _base(ARM_INS_B, 0, "b", "0x100"),            (2, 2, 2)),
        ("bne taken",          _base(ARM_INS_B, 0x100, "bne", "0x100", next_addr=0x100), (2, 2, 2)),
        ("bne not taken",      _base(ARM_INS_B, 0x100, "bne", "0x102", next_addr=0x102), (1, 1, 1)),
        ("mov pc, r0",         _base(ARM_INS_MOV, 0, "mov", "pc, r0"),       (2, 2, 2)),
        ("isb",                _base(ARM_INS_ISB, 0, "isb", ""),             (3, 3, 3)),
        ("mrs",                _base(ARM_INS_MRS, 0, "mrs", "r0, apsr"),     (3, 3, 3)),
        ("nop",                _base(ARM_INS_NOP, 0, "nop", ""),             (1, 1, 1)),
    ]
    ok = True
    for name, got, want in checks:
        status = "ok" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  {status:4} {name:22} {got}  (want {want})")

    # ── Cache-aware branch model ──────────────────────────────────────────
    # Tight 3-instruction loop that fits in one 8-byte line: branch target is
    # always resident -> no flash stall.
    print("\nI-cache behaviour:")
    tight = [
        _mock(ARM_INS_MOV, 0x1000, "movs", "r0, #0"),
        _mock(ARM_INS_ADD, 0x1002, "adds", "r0, #1"),
        _mock(ARM_INS_B,   0x1004, "bne",  "0x1000", size=2),
        _mock(ARM_INS_MOV, 0x1000, "movs", "r0, #0"),
        _mock(ARM_INS_ADD, 0x1002, "adds", "r0, #1"),
        _mock(ARM_INS_B,   0x1004, "bne",  "0x1000", size=2),
    ]
    tight_est = estimate_cycles(tight)
    print(f"  tight loop (1 line)   : {tight_est}  (no miss expected)")

    # Forward branch into a cold line -> one miss, +1 best/upper.
    cold = [
        _mock(ARM_INS_B, 0x2000, "b", "0x2400", size=2),
        _mock(ARM_INS_MOV, 0x2400, "movs", "r0, #0"),
        _mock(ARM_INS_MOV, 0x2402, "movs", "r1, #0"),
    ]
    cold_est = estimate_cycles(cold, warm_cache=False)
    print(f"  cold forward branch   : {cold_est}  (1 miss expected)")
    cold_ok = cold_est.best == cold_est.lower + 1

    assert ok, "BASE SELF-TEST FAILED"
    assert tight_est.lower == tight_est.best == tight_est.upper, "CACHE HIT SELF-TEST FAILED"
    assert cold_ok, "CACHE MISS SELF-TEST FAILED"

    print("\nSelf-test PASSED")

    # ── Reference trace (for a quick sanity read) ─────────────────────────
    trace = [
        _mock(1, 0x0000_0100, "movs", "r0, #0"),
        _mock(1, 0x0000_0102, "adds", "r1, r0, r0"),
        _mock(ARM_INS_LDR, 0x0000_0104, "ldr", "r2, [r0, #4]"),
        _mock(ARM_INS_STR, 0x0000_0106, "str", "r2, [r1, #0]"),
        _mock(ARM_INS_MUL, 0x0000_0108, "muls", "r0, r1, r0"),
        _mock(ARM_INS_BL,  0x0000_010A, "bl",  "some_func"),
        _mock(ARM_INS_B,   0x0000_010E, "b",   "0x100"),
        _mock(ARM_INS_POP, 0x0000_0112, "pop", "{r4,r5,pc}"),
        _mock(1, 0x2000_0000, "movs", "r3, #5"),
        _mock(ARM_INS_MUL, 0x2000_0002, "muls", "r3, r3, r3"),
        _mock(ARM_INS_ISB, 0x2000_0004, "isb", ""),
    ]
    print("\nReference trace breakdown:")
    result = estimate_cycles(trace, verbose=True)
    lo_us, best_us, hi_us = result.to_microseconds()
    print(f"\nResult   : {result}")
    print("At 32 MHz:")
    print(f"  Lower : {lo_us:.3f} us")
    print(f"  Best  : {best_us:.3f} us")
    print(f"  Upper : {hi_us:.3f} us")
