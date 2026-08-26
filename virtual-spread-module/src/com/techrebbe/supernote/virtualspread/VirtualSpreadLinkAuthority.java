package com.techrebbe.supernote.virtualspread;

import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.io.File;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;

/** Pure canonicalization shared by runtime validation and host-side tests. */
public final class VirtualSpreadLinkAuthority {
    private VirtualSpreadLinkAuthority() {}
    private static final String SOURCE_PDF_MARKER =
        "%SNVirtualSpreadSourceSHA256:";
    private static final String PDF_MARKER =
        "%SNVirtualSpreadLinksSHA256:";
    private static final String LAYOUT_PDF_MARKER =
        "%SNVirtualSpreadLayoutSHA256:";

    public static String layout(
        String direction,
        boolean coverSeparate,
        int sourcePageCount,
        int outputPageCount,
        double spreadWidth,
        double spreadHeight,
        double gutter
    ) {
        return "v1|layout|" + direction
            + "|" + (coverSeparate ? "1" : "0")
            + "|" + sourcePageCount
            + "|" + outputPageCount
            + "|" + doubleBits(spreadWidth)
            + "|" + doubleBits(spreadHeight)
            + "|" + doubleBits(gutter);
    }

    public static String layoutDigest(
        String layoutRecord
    ) throws Exception {
        return digest(new String[] {layoutRecord});
    }

    public static String internal(
        int sourcePage,
        String sourceSide,
        int outputPage,
        double x0,
        double y0,
        double x1,
        double y1,
        int targetSourcePage,
        int targetOutputPage,
        String targetSide,
        String targetView
    ) {
        return common(
            "internal",
            sourcePage,
            sourceSide,
            outputPage,
            x0,
            y0,
            x1,
            y1
        ) + "|" + targetSourcePage
            + "|" + targetOutputPage
            + "|" + targetSide
            + "|" + targetView;
    }

    public static String uri(
        int sourcePage,
        String sourceSide,
        int outputPage,
        double x0,
        double y0,
        double x1,
        double y1,
        String uri
    ) throws Exception {
        return common(
            "uri",
            sourcePage,
            sourceSide,
            outputPage,
            x0,
            y0,
            x1,
            y1
        ) + "|" + sha256(strictUtf8(uri));
    }

    public static String digest(String[] records) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (String record : records) {
            digest.update(strictUtf8(record));
            digest.update((byte) '\n');
        }
        return toHex(digest.digest());
    }

    public static String readPdfSourceDigest(File pdf) throws Exception {
        RandomAccessFile input = new RandomAccessFile(pdf, "r");
        try {
            return readPdfSourceDigest(input);
        } finally {
            input.close();
        }
    }

    public static String readPdfSourceDigest(
        RandomAccessFile input
    ) throws Exception {
        long originalPosition = input.getFilePointer();
        try {
            long length = input.length();
            int count = (int) Math.min(length, 4096L);
            if (count <= SOURCE_PDF_MARKER.length() + 65) {
                return null;
            }
            byte[] data = new byte[count];
            input.seek(length - count);
            input.readFully(data);
            String tail = new String(data, StandardCharsets.ISO_8859_1);
            int startxref = tail.lastIndexOf("startxref");
            if (startxref < 0) {
                return null;
            }
            int marker = tail.lastIndexOf(SOURCE_PDF_MARKER, startxref);
            if (marker < 0) {
                return null;
            }
            int digestStart = marker + SOURCE_PDF_MARKER.length();
            int digestEnd = digestStart + 64;
            int nextMarker = digestEnd + 1;
            if (digestEnd >= tail.length()
                || tail.charAt(digestEnd) != '\n'
                || !tail.startsWith(LAYOUT_PDF_MARKER, nextMarker)) {
                return null;
            }
            String digest = tail.substring(digestStart, digestEnd);
            return isSha256(digest) ? digest.toLowerCase() : null;
        } finally {
            input.seek(originalPosition);
        }
    }

    public static String readPdfSourceDigest(
        FileInputStream input
    ) throws Exception {
        return readPdfMarker(
            input,
            SOURCE_PDF_MARKER,
            LAYOUT_PDF_MARKER,
            false
        );
    }

    public static String readPdfDigest(File pdf) throws Exception {
        RandomAccessFile input = new RandomAccessFile(pdf, "r");
        try {
            return readPdfDigest(input);
        } finally {
            input.close();
        }
    }

    public static String readPdfDigest(RandomAccessFile input) throws Exception {
        long originalPosition = input.getFilePointer();
        try {
            long length = input.length();
            int count = (int) Math.min(length, 4096L);
            if (count <= PDF_MARKER.length() + 65) {
                return null;
            }
            byte[] data = new byte[count];
            input.seek(length - count);
            input.readFully(data);
            String tail = new String(data, StandardCharsets.ISO_8859_1);
            int startxref = tail.lastIndexOf("startxref");
            if (startxref < 0) {
                return null;
            }
            int marker = tail.lastIndexOf(PDF_MARKER, startxref);
            if (marker < 0) {
                return null;
            }
            int digestStart = marker + PDF_MARKER.length();
            int digestEnd = digestStart + 64;
            if (digestEnd >= tail.length()
                || tail.charAt(digestEnd) != '\n'
                || digestEnd + 1 != startxref) {
                return null;
            }
            String digest = tail.substring(digestStart, digestEnd);
            return isSha256(digest) ? digest.toLowerCase() : null;
        } finally {
            input.seek(originalPosition);
        }
    }

    public static String readPdfDigest(FileInputStream input) throws Exception {
        return readPdfMarker(input, PDF_MARKER, null, true);
    }

    public static String readPdfLayoutDigest(File pdf) throws Exception {
        RandomAccessFile input = new RandomAccessFile(pdf, "r");
        try {
            return readPdfLayoutDigest(input);
        } finally {
            input.close();
        }
    }

    public static String readPdfLayoutDigest(RandomAccessFile input) throws Exception {
        long originalPosition = input.getFilePointer();
        try {
            long length = input.length();
            int count = (int) Math.min(length, 4096L);
            if (count <= LAYOUT_PDF_MARKER.length() + 65) {
                return null;
            }
            byte[] data = new byte[count];
            input.seek(length - count);
            input.readFully(data);
            String tail = new String(data, StandardCharsets.ISO_8859_1);
            int startxref = tail.lastIndexOf("startxref");
            if (startxref < 0) {
                return null;
            }
            int marker = tail.lastIndexOf(LAYOUT_PDF_MARKER, startxref);
            if (marker < 0) {
                return null;
            }
            int digestStart = marker + LAYOUT_PDF_MARKER.length();
            int digestEnd = digestStart + 64;
            int nextMarker = digestEnd + 1;
            if (digestEnd >= tail.length()
                || tail.charAt(digestEnd) != '\n'
                || !tail.startsWith(PDF_MARKER, nextMarker)) {
                return null;
            }
            String digest = tail.substring(digestStart, digestEnd);
            return isSha256(digest) ? digest.toLowerCase() : null;
        } finally {
            input.seek(originalPosition);
        }
    }

    public static String readPdfLayoutDigest(
        FileInputStream input
    ) throws Exception {
        return readPdfMarker(
            input,
            LAYOUT_PDF_MARKER,
            PDF_MARKER,
            false
        );
    }

    private static String readPdfMarker(
        FileInputStream input,
        String markerText,
        String followingMarker,
        boolean immediatelyBeforeStartxref
    ) throws Exception {
        FileChannel channel = input.getChannel();
        long originalPosition = channel.position();
        try {
            long length = channel.size();
            int count = (int) Math.min(length, 4096L);
            if (count <= markerText.length() + 65) {
                return null;
            }
            ByteBuffer buffer = ByteBuffer.allocate(count);
            channel.position(length - count);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    return null;
                }
            }
            String tail = new String(
                buffer.array(),
                StandardCharsets.ISO_8859_1
            );
            int startxref = tail.lastIndexOf("startxref");
            if (startxref < 0) {
                return null;
            }
            int marker = tail.lastIndexOf(markerText, startxref);
            if (marker < 0) {
                return null;
            }
            int digestStart = marker + markerText.length();
            int digestEnd = digestStart + 64;
            if (digestEnd >= tail.length()
                || tail.charAt(digestEnd) != '\n') {
                return null;
            }
            int next = digestEnd + 1;
            if (immediatelyBeforeStartxref) {
                if (next != startxref) {
                    return null;
                }
            } else if (followingMarker == null
                || !tail.startsWith(followingMarker, next)) {
                return null;
            }
            String digest = tail.substring(digestStart, digestEnd);
            return isSha256(digest) ? digest.toLowerCase() : null;
        } finally {
            channel.position(originalPosition);
        }
    }

    private static String common(
        String kind,
        int sourcePage,
        String sourceSide,
        int outputPage,
        double x0,
        double y0,
        double x1,
        double y1
    ) {
        return "v2|" + kind
            + "|" + sourcePage
            + "|" + sourceSide
            + "|" + outputPage
            + "|" + doubleBits(x0)
            + "|" + doubleBits(y0)
            + "|" + doubleBits(x1)
            + "|" + doubleBits(y1);
    }

    private static String doubleBits(double value) {
        String hex = Long.toHexString(Double.doubleToRawLongBits(value));
        if (hex.length() == 16) {
            return hex;
        }
        StringBuilder padded = new StringBuilder(16);
        for (int index = hex.length(); index < 16; index++) {
            padded.append('0');
        }
        padded.append(hex);
        return padded.toString();
    }

    private static byte[] strictUtf8(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Authority text is missing");
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length()
                    || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException(
                        "Authority text contains an unpaired UTF-16 surrogate"
                    );
                }
                index++;
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException(
                    "Authority text contains an unpaired UTF-16 surrogate"
                );
            }
        }
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String sha256(byte[] value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(value);
        return toHex(digest.digest());
    }

    private static boolean isSha256(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.digit(value.charAt(index), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    private static String toHex(byte[] value) {
        final char[] digits = "0123456789abcdef".toCharArray();
        char[] output = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {

            int current = value[index] & 0xff;
            output[index * 2] = digits[current >>> 4];
            output[index * 2 + 1] = digits[current & 0x0f];
        }
        return new String(output);
    }
}
