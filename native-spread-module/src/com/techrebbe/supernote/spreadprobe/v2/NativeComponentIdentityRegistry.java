package com.techrebbe.supernote.spreadprobe.v2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

/**
 * Process-scoped identity registry with explicit per-runtime leases.
 *
 * A replacement runtime may temporarily share the exact firmware component
 * graph with the runtime it supersedes. Reference-counted leases ensure the
 * retiring runtime cannot delete identities already claimed by its successor.
 */
public final class NativeComponentIdentityRegistry {
    public static final class Lease {
        private final NativeComponentIdentityRegistry owner;
        private final Object[] components;
        private final long[] ids;
        private volatile boolean released;

        private Lease(
            NativeComponentIdentityRegistry owner,
            Object[] components,
            long[] ids
        ) {
            this.owner = owner;
            this.components = components;
            this.ids = ids;
        }

        /** Returns the leased ID only for the exact component and role. */
        public long id(int role, Object component) {
            return owner.id(this, role, component);
        }

        public int size() {
            return components.length;
        }

        public boolean released() {
            return released;
        }
    }

    private static final class Entry {
        final Object component;
        final long id;
        int leaseCount;

        Entry(Object component, long id) {
            this.component = component;
            this.id = id;
            this.leaseCount = 1;
        }
    }

    private final ArrayList<Entry> entries = new ArrayList<>();
    private long nextId = 1L;

    /** Atomically leases stable identity IDs for every role in order. */
    public synchronized Lease acquire(Object... requestedComponents) {
        Objects.requireNonNull(
            requestedComponents,
            "native components are required"
        );
        if (requestedComponents.length == 0) {
            throw new IllegalArgumentException(
                "at least one native component is required"
            );
        }
        Object[] components = requestedComponents.clone();
        long[] ids = new long[components.length];
        int newEntries = 0;
        for (int role = 0; role < components.length; role++) {
            Object component = Objects.requireNonNull(
                components[role],
                "native component is missing"
            );
            Entry entry = find(component);
            if (entry == null && firstIdentityIndex(components, role) == role) {
                newEntries++;
            }
            if (entry != null) {
                int occurrences = identityOccurrences(components, component);
                if (entry.leaseCount > Integer.MAX_VALUE - occurrences) {
                    throw new IllegalStateException(
                        "native component identity lease count exhausted"
                    );
                }
            }
        }
        if (nextId <= 0L
            || newEntries > 0
                && nextId > Long.MAX_VALUE - (long) newEntries + 1L) {
            throw new IllegalStateException(
                "native component identity exhausted"
            );
        }

        for (int role = 0; role < components.length; role++) {
            Object component = components[role];
            Entry entry = find(component);
            if (entry == null) {
                entry = new Entry(component, nextId++);
                entries.add(entry);
            } else {
                entry.leaseCount++;
            }
            ids[role] = entry.id;
        }
        return new Lease(this, components, ids);
    }

    /** Releases exactly one runtime lease; other runtime claims remain live. */
    public synchronized void release(Lease lease) {
        if (lease == null) return;
        if (lease.owner != this) {
            throw new IllegalArgumentException(
                "native component identity lease belongs to another registry"
            );
        }
        if (lease.released) return;
        for (int role = 0; role < lease.components.length; role++) {
            Object component = lease.components[role];
            long id = lease.ids[role];
            Entry entry = find(component);
            if (entry == null || entry.id != id || entry.leaseCount <= 0) {
                throw new IllegalStateException(
                    "native component identity lease authority was lost"
                );
            }
            entry.leaseCount--;
            if (entry.leaseCount == 0) entries.remove(entry);
        }
        lease.released = true;
        Arrays.fill(lease.components, null);
    }

    private synchronized long id(
        Lease lease,
        int role,
        Object component
    ) {
        if (lease.owner != this || lease.released) {
            throw new IllegalStateException(
                "native component identity lease is released or foreign"
            );
        }
        if (role < 0 || role >= lease.components.length) {
            throw new IllegalArgumentException(
                "native component identity role is out of range"
            );
        }
        if (lease.components[role] != component) {
            throw new IllegalStateException(
                "native component identity changed within a lease"
            );
        }
        Entry entry = find(component);
        if (entry == null || entry.id != lease.ids[role]
            || entry.leaseCount <= 0) {
            throw new IllegalStateException(
                "native component identity lease authority was lost"
            );
        }
        return entry.id;
    }

    private Entry find(Object component) {
        for (Entry entry : entries) {
            if (entry.component == component) return entry;
        }
        return null;
    }

    private static int firstIdentityIndex(Object[] values, int limit) {
        Object target = values[limit];
        for (int index = 0; index < limit; index++) {
            if (values[index] == target) return index;
        }
        return limit;
    }

    private static int identityOccurrences(Object[] values, Object target) {
        int count = 0;
        for (Object value : values) {
            if (value == target) count++;
        }
        return count;
    }
}
