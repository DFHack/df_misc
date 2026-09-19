==================================
Job assignment internals (v53.x)
==================================

Notes from reverse-engineering how Dwarf Fortress assigns and interrupts
unit jobs. Verified on **v0.53.16 Windows Steam** by external memory
sampling (``ReadProcessMemory``) of a live fortress combined with in-game
Lua probing. Field/type names follow df-structures; see
``library/xml/df.job.xml``.

.. contents:: Contents
    :local:


The auction model
=================

Job assignment is a periodic **auction**, not a scheduler:

1. DF maintains ``world.jobs.postings`` — a persistent
   ``stl-vector<job_postingst*>`` advertising unclaimed jobs.
2. During a job-assignment *pass*, every candidate unit evaluates live
   postings and pushes a ``job_applicationst`` per (unit, posting) pair
   into ``world.jobs.job_application_heap`` — a **max-heap** of 2000
   fixed slots keyed by ``value``.
3. The highest-valued application for a posting wins; the winner's
   ``unit.job.current_job`` is set to the posting's job.
4. The heap is **populated and drained within a single pass**, which
   completes in well under a millisecond. At any tick boundary the heap
   reads ``size == 0`` — this is why DFHack/Lua polling never observes
   applications in flight.

``job_applicationst`` layout (16 bytes):

=========  ===============  ==========================================
offset     field            meaning
=========  ===============  ==========================================
0x00       applicant        ``unit*``
0x08       posting_index    index into ``world.jobs.postings``
0x0c       value            int32 bid score; max wins the posting
=========  ===============  ==========================================

``job_postingst`` layout:

=========  ============================  =============================
offset     field                         meaning
=========  ============================  =============================
0x00       idx                           == vector position
0x08       job                           ``job*`` (NULL/garbage if dead)
0x10       flags                         ``dead`` bit = 0x1
0x14       rough_number_of_applications  application counter, unsaved
=========  ============================  =============================

``postings`` entries are **never removed**: consumed entries get
``flags.dead`` and a NULL job, and dead slots are **recycled** for new
jobs within frames. Never resolve ``posting_index`` against the vector
after the pass has drained — the index may already refer to a different
job. Resolve ``posting->job`` only while the heap capture is fresh, and
treat ``job == NULL`` as authoritative (dead).

Relevant ``job`` fields: ``job_type`` @ +20 (int32), ``flags`` @ +44
(uint32). Flag bits: ``repeat``=0, ``suspend``=1, ``working``=2,
``fetching``=3, ``special``=4, ``do_now``=18.


Observed value bands
====================

``value`` is an additive score. Empirical bands (v0.53.16, ~200-unit
fortress):

==============  ======================================================
value           interpretation
==============  ======================================================
~9,500-15,000   baseline bids, including units lacking the labor
~30k-170k       distance/labor-tuned bids
~435k / ~615k   higher-tier bonuses (exact source not isolated)
~1,050,000      **continuation** — unit re-bidding the job-type it is
                already doing; keeps it on task
~20,000,000     **urgent** — ``job.flags.do_now`` (verified: +20,000,000
                on top of the base score, e.g. 20,009,xxx-20,014,xxx),
                and unit-sourced ``special`` need jobs (Sleep confirmed)
==============  ======================================================

The same unit's bids on different postings differ by small amounts
(distance etc.); posting-side bonuses dominate the large jumps.

**``do_now``** (``DO_ME_NOW``) was verified by controlled experiment:
setting the flag on all pending postings flooded the heap with
``val > 20,000,000`` applications; clearing it removed them. It is a
blunt, posting-level outbid — it does not select a specific unit, and it
does not appear to instantly yank a unit out of an in-progress job phase
(observed transitions happened at completion/phase boundaries). This is
the granularity limitation described in DFHack/dfhack#3245.


What interrupts a task
======================

Observed drivers of visible "Urist stopped working" behavior:

- **Need thresholds** — when hunger/thirst/drowsiness counters cross a
  threshold (hunger ≈ 40,000, thirst ≈ 21,000, drowsiness ≈ 50,000
  observed), a unit-sourced ``special`` job (Eat/Drink/Sleep) is posted
  at the ~20M band and outbids whatever the unit is doing.
- **Claim races** — a unit pathing to a posting loses it to a faster
  claimer; its ``current_job`` is invalidated → drops to no job →
  re-evaluates. This is the common "turned around mid-walk" interrupt.
- **Outbidding** — a posting whose value exceeds the ~1M continuation
  bonus pulls a unit off its current job at the next pass.
- **``do_now``** — the +20M outbid above.
- **Validation failures** — ~120 ``killjob_exception_type`` reasons
  (pathing, item loss, incapacity, mood, combat, etc.) produce
  "Urist cancels X" announcements; see ``df.job.xml`` for the enum and
  ``jobcancel_announce`` for the standing-order toggle.

True mid-swing preemption is rare; most apparent interrupts are
claim-loss or a need threshold crossing at a re-evaluation boundary.


Reproducing the observations
============================

In-process Lua cannot see the heap mid-pass (it lives inside the tick).
Two complementary approaches were used:

External heap sampler
---------------------

``job_heap_sampler.py`` (repo root) opens the DF process and polls the
heap ``size`` field at high frequency, dumping each non-empty batch with
resolved unit ids and posting→job metadata. It needs per-build
constants; the file header documents how to derive them. For v0.53.16
Windows Steam:

- ``world`` global RVA = ``0x1423d14f0`` (symbols.xml STEAM stanza);
  absolute = module_base + (RVA - 0x140000000)
- ``world.jobs`` @ +0x14cc0; ``postings`` vector @ +0x14ce0;
  ``job_application_heap`` @ +0x14cf8; heap ``size`` @ heap+0x7d00
- ``unit.id`` @ +0x130; ``unit.job.current_job`` @ +0x1970

Caveats:

- The heap can contain torn/stale entries mid-write; dedupe by
  (posting, unit) and distrust single outliers.
- Winning (highest-value) postings are consumed *during* the pass, so
  their ``posting->job`` usually reads NULL by the time a capture lands.
  To identify what a high-value bid was for, read the winner's
  ``unit.job.current_job`` a few ms after the batch.
- 64-bit ``ReadProcessMemory`` requires ``ctypes.c_void_p`` argtypes or
  addresses overflow; capstone needs ``md.detail = True`` before reading
  ``insn.operands``.

Lua transition watcher
----------------------

A per-frames ``dfhack.timeout`` watcher recording
``unit.job.current_job`` transitions (job id + type + unit need counters)
to a file cleanly shows *outcomes*: job→none→job phase transitions,
need-driven switches (Eat/Drink/Sleep), completion chains
(PlantSeeds → HarvestPlants → StoreItemInBarrel), and claim-loss drops.
It cannot see the losing bids — only the external sampler can.

Static analysis
---------------

The assignment code is reachable via xrefs to the heap object (it is an
inline member of ``job_handlerst``, itself a member of ``world``, so code
reaches it through the ``world`` global — xref the ``world`` symbol and
trace the +0x14cf8-style member offsets). Useful landmarks in symbols.xml
(v0.53.16 STEAM): ``job_handlerst::remove_job`` vmethod,
``job_next_id``, ``process_jobs``/``process_dig`` trigger flags.

``jobvalue`` (int32[258], indexed by job_type) and ``jobvalue_setter``
(unit*[258]) are registered in DF's field-registration pass but read
zero at all times on this build — likely vestigial or debug-only in
53.16; do not rely on them.

Detection landmark (per ab9rf, DFHack/scripts#1639):
``worldst::handle_job_applications`` pushes a crashlog minidump entry
of type ``0xf`` when it starts processing and removes it when done —
polling the crashlog minidump list is a deterministic way to observe
when an auction pass is in flight, complementing heap-size polling.
The function is at ``0x140d0d4d0`` in v0.50.16 Steam/Windows (it
takes a few days to relocate after each release; Linux builds are not
analyzed because gcc output decompiles poorly).


Open questions
==============

- Per ab9rf (df-structures#908): the auction implementation is already
  known to maintainers as ``worldst::handle_job_applications`` — not a
  symbols.xml global, but reachable via Ghidra/xrefs. Decompiling it
  would settle everything below; the sampler data provides ground-truth
  inputs/outputs to check against.
- Exact composition of the base score (distance metric, labor-match
  weighting, unit preferences) — the additive ~9.5k/14.5k/80k/etc.
  sub-bands are empirical, not decompiled.
- Whether eligibility gates *application* or only *winner selection*
  (ineligible units were observed bidding on ``do_now`` postings).
- The 435k/615k band sources.
- Whether a ``working`` (in-progress) job re-posted after interruption
  gets a resume bonus distinct from the ~1M continuation.
