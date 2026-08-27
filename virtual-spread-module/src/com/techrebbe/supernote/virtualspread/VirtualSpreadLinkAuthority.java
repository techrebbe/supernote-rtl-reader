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
    private static final String MAPPING_PDF_MARKER =
        "%SNVirtualSpreadMappingSHA256:";
    private static final String VIEW_PDF_MARKER =
        "%SNVirtualSpreadViewSHA256:";
    private static final String MAPPING_DOMAIN =
        "techrebbe.supernote.virtual-spread-mapping/v1";
    private static final String VIEW_DOMAIN =
        "techrebbe.supernote.virtual-spread-view/v1";
    private static final String VIEW_PREFIX = "inkbridge-view-v1-";
    private static final String DOCUMENT_PREFIX = "inkbridge-doc-v1-";

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

    public static String mapping(
        int sourcePageIndex,
        int virtualPageIndex,
        String side,
        int sourceRotation,
        double[] sourceBox,
        double[] normalizedSourceBox,
        double[] slot,
        double[] destination,
        double scale,
        double[] transform
    ) {
        if (sourcePageIndex < 0 || virtualPageIndex < 0
            || !("left".equals(side) || "right".equals(side))
            || !(sourceRotation == 0 || sourceRotation == 90
                || sourceRotation == 180 || sourceRotation == 270)
            || !finiteArray(sourceBox, 4)
            || !finiteArray(normalizedSourceBox, 4)
            || !finiteArray(slot, 4)
            || !finiteArray(destination, 4)
            || !Double.isFinite(scale) || scale <= 0.0
            || !finiteArray(transform, 6)) {
            throw new IllegalArgumentException("Invalid mapping record");
        }
        StringBuilder record = new StringBuilder("page")
            .append('|').append(sourcePageIndex)
            .append('|').append(virtualPageIndex)
            .append('|').append(side)
            .append('|').append(sourceRotation);
        appendBits(record, sourceBox);
        appendBits(record, normalizedSourceBox);
        appendBits(record, slot);
        appendBits(record, destination);
        record.append('|').append(doubleBits(scale));
        appendBits(record, transform);
        return record.toString();
    }

    public static String mappingDigest(String[] records) throws Exception {
        if (records == null || records.length == 0) {
            throw new IllegalArgumentException("Mapping records are missing");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(strictUtf8(MAPPING_DOMAIN));
        digest.update((byte) '\n');
        for (String record : records) {
            digest.update(strictUtf8(record));
            digest.update((byte) '\n');
        }
        return toHex(digest.digest());
    }

    public static String viewId(
        String sourceSha256,
        String manifestSchema,
        String generatorVersion,
        String direction,
        boolean coverSeparate,
        double spreadWidth,
        double spreadHeight,
        double gutter,
        String mappingSha256
    ) throws Exception {
        if (!isLowerSha256(sourceSha256)
            || !isLowerSha256(mappingSha256)
            || !"techrebbe.supernote.virtual-spread/v3".equals(
                manifestSchema)
            || !"techrebbe.supernote.virtual-spread-generator/v1".equals(
                generatorVersion)
            || !"rtl".equals(direction)
            || !Double.isFinite(spreadWidth)
            || !Double.isFinite(spreadHeight)
            || !Double.isFinite(gutter)) {
            throw new IllegalArgumentException("Invalid view identity");
        }
        String canonical = VIEW_DOMAIN
            + "\nsource|" + sourceSha256
            + "\nschema|" + manifestSchema
            + "\ngenerator|" + generatorVersion
            + "\ndirection|" + direction
            + "\ncover|" + (coverSeparate ? "1" : "0")
            + "\nspread|" + doubleBits(spreadWidth)
            + "|" + doubleBits(spreadHeight)
            + "|" + doubleBits(gutter)
            + "\nmapping|" + mappingSha256
            + "\n";
        return VIEW_PREFIX + sha256(strictUtf8(canonical));
    }

    public static String documentId(String sourceSha256) {
        if (!isLowerSha256(sourceSha256)) {
            throw new IllegalArgumentException("Invalid document identity");
        }
        return DOCUMENT_PREFIX + sourceSha256;
    }

    public static String outputBasename(
        String sourceSha256,
        String viewId
    ) {
        if (!isViewId(viewId)) {
            throw new IllegalArgumentException("Invalid view identity");
        }
        return documentId(sourceSha256) + "." + viewId
            + ".virtual-spread.pdf";
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
        return readPdfMarker(
            input, SOURCE_PDF_MARKER, LAYOUT_PDF_MARKER, false
        );
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
        return readPdfMarker(input, PDF_MARKER, MAPPING_PDF_MARKER, false);
    }

    public static String readPdfDigest(FileInputStream input) throws Exception {
        return readPdfMarker(
            input, PDF_MARKER, MAPPING_PDF_MARKER, false
        );
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
        return readPdfMarker(
            input, LAYOUT_PDF_MARKER, PDF_MARKER, false
        );
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

    public static String readPdfMappingDigest(File pdf) throws Exception {
        RandomAccessFile input = new RandomAccessFile(pdf, "r");
        try {
            return readPdfMappingDigest(input);
        } finally {
            input.close();
        }
    }

    public static String readPdfMappingDigest(
        RandomAccessFile input
    ) throws Exception {
        return readPdfMarker(
            input, MAPPING_PDF_MARKER, VIEW_PDF_MARKER, false
        );
    }

    public static String readPdfMappingDigest(
        FileInputStream input
    ) throws Exception {
        return readPdfMarker(
            input, MAPPING_PDF_MARKER, VIEW_PDF_MARKER, false
        );
    }

    public static String readPdfViewDigest(File pdf) throws Exception {
        RandomAccessFile input = new RandomAccessFile(pdf, "r");
        try {
            return readPdfViewDigest(input);
        } finally {
            input.close();
        }
    }

    public static String readPdfViewDigest(
        RandomAccessFile input
    ) throws Exception {
        return readPdfMarker(input, VIEW_PDF_MARKER, null, true);
    }

    public static String readPdfViewDigest(
        FileInputStream input
    ) throws Exception {
        return readPdfMarker(input, VIEW_PDF_MARKER, null, true);
    }

    private static String readPdfMarker(
        RandomAccessFile input,
        String markerText,
        String followingMarker,
        boolean immediatelyBeforeStartxref
    ) throws Exception {
        long originalPosition = input.getFilePointer();
        try {
            long length = input.length();
            int count = (int) Math.min(length, 4096L);
            if (count <= markerText.length() + 65) {
                return null;
            }
            byte[] data = new byte[count];
            input.seek(length - count);
            input.readFully(data);
            return markerValue(
                new String(data, StandardCharsets.ISO_8859_1),
                markerText,
                followingMarker,
                immediatelyBeforeStartxref
            );
        } finally {
            input.seek(originalPosition);
        }
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
            return markerValue(
                tail,
                markerText,
                followingMarker,
                immediatelyBeforeStartxref
            );
        } finally {
            channel.position(originalPosition);
        }
    }

    private static String markerValue(
        String tail,
        String markerText,
        String followingMarker,
        boolean immediatelyBeforeStartxref
    ) {
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
        if (digestEnd >= tail.length() || tail.charAt(digestEnd) != '\n') {
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
        return isLowerSha256(digest) ? digest : null;
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

    private static boolean finiteArray(double[] values, int length) {
        if (values == null || values.length != length) {
            return false;
        }
        for (double value : values) {
            if (!Double.isFinite(value)) {
                return false;
            }
        }
        return true;
    }

    private static void appendBits(StringBuilder record, double[] values) {
        for (double value : values) {
            record.append('|').append(doubleBits(value));
        }
    }

    private static boolean isLowerSha256(String value) {
        if (!isSha256(value)) {
            return false;
        }
        return value.equals(value.toLowerCase(java.util.Locale.ROOT));
    }

    private static boolean isViewId(String value) {
        return value != null
            && value.startsWith(VIEW_PREFIX)
            && isLowerSha256(value.substring(VIEW_PREFIX.length()));
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
