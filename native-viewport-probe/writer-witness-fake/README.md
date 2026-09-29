# Writer witness fake-service probe (offline only)

This is a deterministic C++ host model of a *proposed* native page/writer
witness, not an implementation for the stock service. It does not access Nomad,
Binder, JNI, the pen device, or any production artifact. Passing it cannot
establish that the pinned firmware provides the modeled gate or generation;
`NATIVE_WRITER_AUTHORITY.md` remains **NO-GO / UNKNOWN** for live admission.

From this directory, with Strawberry `g++` on Windows:

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -Werror -static -pthread writer_witness_fake_test.cpp -o writer_witness_fake_test.exe
.\writer_witness_fake_test.exe
```

The fake routes independent Java and JNI setter entries through one state gate.
Each accepted entry advances a non-reusable epoch before separately mutating
page/layer, the region vector, and the writable flag. A same-gate snapshot is
unavailable throughout every pending phase; a mid-write failure permanently
poisons the fake witness even though its internal state is partially changed.
The snapshot also binds process and service incarnations. A simulated process
restart resets its local service sequence, yet an identical state and epoch
cannot reuse the earlier witness because the process incarnation changes. The
fake process is non-copyable and allocates distinct service IDs across
concurrent constructors.

The fake pen appends a trail under the same gate as its final witness check:
the writer cannot advance between that check and the modeled side effect, and
a false writable flag never appends a trail. An exception after epoch admission
poisons the witness and clears pending rather than exposing partial success.
Detach closes callback admission, waits for in-flight callbacks, and flushes
once even when two callers detach concurrently. A later caller can complete
the flush after a test-injected first-caller drain timeout; admission remains
closed throughout. The tests use predicate-based
condition variables with bounded watchdog waits and scoped release/join; they
do not use sleeps. An injected callback-side snapshot exception closes
admission and drains the callback count; a setter-side gate probe confirms it
encounters the pen-held gate. The white-box partial-state reader is test-only
and is not a proposed production getter. Real service incarnation, gate coverage, pen
ordering, and detach behavior still require independent evidence; the fake's
incarnation allocator is not a substitute for a real authenticated source.
