#!/usr/bin/env python3
"""Sample DF's job application binary heap from outside the process.

DF's job-assignment pass populates and drains
``world.jobs.job_application_heap`` within a single simulation tick
(sub-millisecond bursts), so in-process DFHack/Lua polling at tick
boundaries almost never catches it populated. Reading process memory at
high frequency from an external process does catch it.

Each captured entry is a ``job_applicationst``:

    offset  field            type
    0x00    applicant        unit*
    0x08    posting_index    int32 (index into world.jobs.postings)
    0x0c    value            int32 (bid score; max wins the posting)

Verified on DF v0.53.16 Windows Steam. See doc/job-assignment.rst for the
full writeup.

How to find the constants below for a new DF version:
    1. Get the module base of Dwarf Fortress.exe (ASLR): read the PID's
       module list, or have DFHack print a known address.
    2. WORLD_RVA: the ``world`` symbol RVA from symbols.xml for this build.
    3. Member offsets: run ``dfhack-run lua`` on the live game:
           local w = tonumber(tostring(df.global.world):match('0x(%x+)'),16)
           for each of jobs / jobs.postings / jobs.job_application_heap,
           print(tostring(x)) and subtract w.
    4. UNIT_ID_OFF / UNIT_CURJOB_OFF: same technique with
       tostring(unit) vs the field, or scan a unit's memory for a known
       job pointer.

Usage: python job_heap_sampler.py <pid> [duration_seconds]
"""

import ctypes
import ctypes.wintypes as W
import struct
import sys
import time

# ---- v0.53.16 Windows Steam constants (see header for how to re-derive) ----
EXE_BASE = None            # filled at runtime via module enumeration
WORLD_RVA = 0x1423D14F0    # 'world' symbol, STEAM stanza of symbols.xml
IMAGE_BASE = 0x140000000   # PE preferred base used by symbols.xml RVAs

JOBS_OFF = 0x14CC0         # world.jobs (job_handlerst)
POSTINGS_VEC_OFF = 0x14CE0 # world.jobs.postings (stl-vector<job_postingst*>)
HEAP_OFF = 0x14CF8         # world.jobs.job_application_heap (inline array)
HEAP_NODES = 2000
HEAP_SIZE_OFF = 0x7D00     # HEAP_NODES * sizeof(job_applicationst=16)

UNIT_ID_OFF = 0x130        # unit.id
UNIT_CURJOB_OFF = 0x1970   # unit.job.current_job

# job_postingst layout: idx@0, job*@8, flags@16, rough_apps@20
# job layout: job_type@20 (int32), flags@44 (uint32); do_now = bit 18,
# working = bit 2, special = bit 4.

k32 = ctypes.WinDLL('kernel32')
k32.OpenProcess.restype = W.HANDLE
k32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
k32.ReadProcessMemory.restype = W.BOOL
k32.ReadProcessMemory.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
psapi = ctypes.WinDLL('psapi')
psapi.EnumProcessModulesEx.restype = W.BOOL


def get_base(pid):
    h = k32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        sys.exit('cannot open pid %d' % pid)
    mods = (W.HMODULE * 1024)()
    need = W.DWORD(0)
    psapi.EnumProcessModulesEx(h, mods, ctypes.sizeof(mods),
                               ctypes.byref(need), 3)
    k32.CloseHandle(h)
    return mods[0]  # first module is the exe


def main():
    pid = int(sys.argv[1])
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
    base = get_base(pid)
    world = base + (WORLD_RVA - IMAGE_BASE)
    heap = world + HEAP_OFF
    hsize = heap + HEAP_SIZE_OFF
    pvec = world + POSTINGS_VEC_OFF
    print('base=%x world=%x heap=%x postings=%x' % (base, world, heap, pvec))

    h = k32.OpenProcess(0x1F0FFF, False, pid)

    def rd(addr, size):
        buf = (ctypes.c_ubyte * size)()
        n = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                 ctypes.byref(n)):
            return bytes(buf[:n.value])
        return None

    def ri32(addr):
        b = rd(addr, 4)
        return struct.unpack('<i', b)[0] if b else None

    def rptr(addr):
        b = rd(addr, 8)
        return struct.unpack('<q', b)[0] if b else 0

    t0 = time.time()
    last_size = -1
    batches = 0
    while time.time() - t0 < duration:
        sz = ri32(hsize)
        if sz is None or sz <= 0 or sz == last_size:
            continue
        last_size = sz
        data = rd(heap, min(sz, HEAP_NODES) * 16)
        pbase = rptr(pvec)  # postings vector begin
        if not data or not pbase:
            continue
        batches += 1
        print('--- batch t=%.3f size=%d ---' % (time.time() - t0, sz))
        for i in range(min(sz, HEAP_NODES)):
            app, pi, val = struct.unpack_from('<qii', data, i * 16)
            uid = ri32(app + UNIT_ID_OFF)
            # resolve posting -> job while it is (hopefully) still live
            pp = rptr(pbase + pi * 8)
            jt, jfl = -1, -1
            if pp:
                jp = rptr(pp + 8)
                if jp:
                    # postings are recycled mid-pass; a dead slot yields a
                    # stale job pointer and garbage job_type. Sanity-bound it.
                    jt = ri32(jp + 20)
                    if jt is not None and not (0 <= jt < 260):
                        jt, jfl = -1, -1
                    else:
                        jfl = ri32(jp + 44)
            print('  post=%4d uid=%6d val=%9d jt=%s jfl=%s'
                  % (pi, uid, val, jt, hex(jfl) if jfl >= 0 else '-'))
    print('done; %d non-empty captures' % batches)


if __name__ == '__main__':
    main()
