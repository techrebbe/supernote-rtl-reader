package com.techrebbe.supernote.spreadprobe.v2;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;

/**
 * Pure codec for the fixed-inode Native Reader v2 authority journal.
 *
 * <p>The file is exactly two fixed-size slots. A writer updates only the
 * inactive slot and never renames, truncates, resizes, deletes, or recreates
 * the journal after initialization. A non-zero malformed slot invalidates the
 * complete journal instead of falling back to older authority. This is the
 * fail-closed property required while a fixed-offset write is incomplete.</p>
 */
public final class NativeReaderV2AuthorityJournal {
    public static final int FORMAT_VERSION = 3;
    public static final int SLOT_COUNT = 2;
    public static final int SLOT_SIZE = 16 * 1024;
    public static final int FILE_SIZE = SLOT_COUNT * SLOT_SIZE;
    public static final int HEADER_SIZE = 128;
    public static final int MAX_PAYLOAD_SIZE = SLOT_SIZE - HEADER_SIZE;

    private static final byte[] MAGIC = new byte[] {
        'S', 'N', 'R', 'V', '2', 'J', '3', 0
    };
    private static final byte[] RECORD_DOMAIN =
        "supernote-native-reader-v2-authority-slot-v3\0".getBytes(
            StandardCharsets.US_ASCII
        );
    private static final int PAYLOAD_DIGEST_OFFSET = 40;
    private static final int RECORD_DIGEST_OFFSET = 72;
    private static final int RESERVED_OFFSET = 104;

    private NativeReaderV2AuthorityJournal() {}

    public enum State {
        OFF(1),
        PENDING(2),
        COMMITTED(3),
        RECOVERY(4);

        public final int code;

        State(int code) {
            this.code = code;
        }

        static State fromCode(int code) {
            for (State state : values()) {
                if (state.code == code) return state;
            }
            throw new IllegalArgumentException("unknown journal state " + code);
        }
    }

    public static final class Record {
        public final int slotIndex;
        public final State state;
        public final long generation;
        public final byte[] payload;
        public final String payloadSha256;
        public final String authoritySha256;

        private Record(
            int slotIndex,
            State state,
            long generation,
            byte[] payload,
            byte[] payloadDigest,
            byte[] authorityDigest
        ) {
            this.slotIndex = slotIndex;
            this.state = state;
            this.generation = generation;
            this.payload = payload.clone();
            this.payloadSha256 = hex(payloadDigest);
            this.authoritySha256 = hex(authorityDigest);
        }
    }

    public static final class Snapshot {
        public final Record current;
        public final Record other;

        private Snapshot(Record current, Record other) {
            this.current = current;
            this.other = other;
        }

        public boolean isEmpty() {
            return current == null;
        }

        public long nextGeneration() {
            if (current == null) return 1L;
            if (current.generation == Long.MAX_VALUE) {
                throw new IllegalStateException("journal generation exhausted");
            }
            return current.generation + 1L;
        }

        public int inactiveSlotIndex() {
            return current == null ? 0 : 1 - current.slotIndex;
        }
    }

    public static byte[] emptyFile() {
        return new byte[FILE_SIZE];
    }

    /** Returns a complete fixed-size image with one slot replaced. */
    public static byte[] withRecord(
        byte[] journal,
        int slotIndex,
        State state,
        long generation,
        byte[] payload
    ) {
        requireFileSize(journal);
        byte[] result = journal.clone();
        byte[] slot = encodeSlot(slotIndex, state, generation, payload);
        System.arraycopy(slot, 0, result, slotIndex * SLOT_SIZE, SLOT_SIZE);
        return result;
    }

    /** Encodes one slot. The writer must publish payload before this header. */
    public static byte[] encodeSlot(
        int slotIndex,
        State state,
        long generation,
        byte[] payload
    ) {
        requireSlotIndex(slotIndex);
        if (state == null || generation <= 0L || payload == null
            || payload.length == 0 || payload.length > MAX_PAYLOAD_SIZE) {
            throw new IllegalArgumentException("invalid journal record");
        }
        byte[] payloadDigest = sha256(payload);
        byte[] recordDigest = recordDigest(
            slotIndex,
            state,
            generation,
            payload.length,
            payloadDigest,
            payload
        );
        byte[] slot = new byte[SLOT_SIZE];
        System.arraycopy(payload, 0, slot, HEADER_SIZE, payload.length);
        ByteBuffer header = ByteBuffer.wrap(slot).order(ByteOrder.BIG_ENDIAN);
        header.put(MAGIC);
        header.putInt(FORMAT_VERSION);
        header.putInt(HEADER_SIZE);
        header.putInt(SLOT_SIZE);
        header.putInt(state.code);
        header.putLong(generation);
        header.putInt(payload.length);
        header.putInt(0);
        header.put(payloadDigest);
        header.put(recordDigest);
        // Bytes 104..127 are reserved and remain zero.
        return slot;
    }

    /**
     * Parses both slots. Any non-zero invalid slot rejects the whole file so a
     * torn newer transition cannot revive a valid but stale older record.
     */
    public static Snapshot inspect(byte[] journal) {
        requireFileSize(journal);
        Record first = parseSlot(journal, 0);
        Record second = parseSlot(journal, 1);
        if (first == null && second == null) return new Snapshot(null, null);
        if (first == null) return new Snapshot(second, null);
        if (second == null) return new Snapshot(first, null);
        if (first.generation == second.generation) {
            throw new IllegalArgumentException(
                "journal slots reuse one generation"
            );
        }
        return first.generation > second.generation
            ? new Snapshot(first, second)
            : new Snapshot(second, first);
    }

    private static Record parseSlot(byte[] journal, int slotIndex) {
        int offset = slotIndex * SLOT_SIZE;
        if (allZero(journal, offset, SLOT_SIZE)) return null;
        byte[] slot = Arrays.copyOfRange(journal, offset, offset + SLOT_SIZE);
        ByteBuffer header = ByteBuffer.wrap(slot).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        header.get(magic);
        if (!Arrays.equals(MAGIC, magic)
            || header.getInt() != FORMAT_VERSION
            || header.getInt() != HEADER_SIZE
            || header.getInt() != SLOT_SIZE) {
            throw new IllegalArgumentException(
                "invalid journal slot header " + slotIndex
            );
        }
        State state = State.fromCode(header.getInt());
        long generation = header.getLong();
        int payloadLength = header.getInt();
        int reserved = header.getInt();
        if (generation <= 0L || payloadLength <= 0
            || payloadLength > MAX_PAYLOAD_SIZE || reserved != 0
            || !allZero(slot, RESERVED_OFFSET, HEADER_SIZE - RESERVED_OFFSET)) {
            throw new IllegalArgumentException(
                "invalid journal slot bounds " + slotIndex
            );
        }
        byte[] claimedPayloadDigest = Arrays.copyOfRange(
            slot,
            PAYLOAD_DIGEST_OFFSET,
            RECORD_DIGEST_OFFSET
        );
        byte[] claimedRecordDigest = Arrays.copyOfRange(
            slot,
            RECORD_DIGEST_OFFSET,
            RESERVED_OFFSET
        );
        byte[] payload = Arrays.copyOfRange(
            slot,
            HEADER_SIZE,
            HEADER_SIZE + payloadLength
        );
        if (!allZero(
                slot,
                HEADER_SIZE + payloadLength,
                SLOT_SIZE - HEADER_SIZE - payloadLength
            )) {
            throw new IllegalArgumentException(
                "journal slot has unauthenticated tail " + slotIndex
            );
        }
        byte[] actualPayloadDigest = sha256(payload);
        if (!MessageDigest.isEqual(
                claimedPayloadDigest,
                actualPayloadDigest
            )) {
            throw new IllegalArgumentException(
                "journal payload digest mismatch " + slotIndex
            );
        }
        byte[] actualRecordDigest = recordDigest(
            slotIndex,
            state,
            generation,
            payloadLength,
            actualPayloadDigest,
            payload
        );
        if (!MessageDigest.isEqual(
                claimedRecordDigest,
                actualRecordDigest
            )) {
            throw new IllegalArgumentException(
                "journal record digest mismatch " + slotIndex
            );
        }
        return new Record(
            slotIndex,
            state,
            generation,
            payload,
            actualPayloadDigest,
            actualRecordDigest
        );
    }

    private static byte[] recordDigest(
        int slotIndex,
        State state,
        long generation,
        int payloadLength,
        byte[] payloadDigest,
        byte[] payload
    ) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(
                RECORD_DOMAIN.length + 64 + payloadLength
            );
            DataOutputStream output = new DataOutputStream(bytes);
            output.write(RECORD_DOMAIN);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(SLOT_SIZE);
            output.writeInt(slotIndex);
            output.writeInt(state.code);
            output.writeLong(generation);
            output.writeInt(payloadLength);
            output.write(payloadDigest);
            output.write(payload);
            output.flush();
            return sha256(bytes.toByteArray());
        } catch (Exception impossible) {
            throw new IllegalStateException(
                "could not encode journal digest input",
                impossible
            );
        }
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            value.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return value.toString();
    }

    private static boolean allZero(byte[] bytes, int offset, int length) {
        for (int index = offset; index < offset + length; index++) {
            if (bytes[index] != 0) return false;
        }
        return true;
    }

    private static void requireFileSize(byte[] journal) {
        if (journal == null || journal.length != FILE_SIZE) {
            throw new IllegalArgumentException("invalid journal file size");
        }
    }

    private static void requireSlotIndex(int slotIndex) {
        if (slotIndex < 0 || slotIndex >= SLOT_COUNT) {
            throw new IllegalArgumentException("invalid journal slot index");
        }
    }
}
