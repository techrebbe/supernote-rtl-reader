package com.techrebbe.supernote.virtualspread;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Canonical bookmark authority shared with the Python v4 generator. */
public final class VirtualSpreadNavigationAuthority {
    private static final String DOMAIN =
        "techrebbe.supernote.virtual-spread-navigation/v1";

    private VirtualSpreadNavigationAuthority() {}

    public static String record(
        int index,
        Integer parentIndex,
        String title,
        boolean isOpen,
        boolean bold,
        boolean italic,
        double[] color,
        Integer sourcePageIndex,
        Integer virtualPageIndex,
        String side,
        String targetView,
        String mode,
        Double[] operands
    ) throws Exception {
        if (index < 0
            || (parentIndex != null
                && (parentIndex.intValue() < 0
                    || parentIndex.intValue() >= index))
            || title == null || title.indexOf('\0') >= 0
            || color == null || color.length != 3
            || !finite(color) || !unitColor(color)
            || !wellFormedUtf16(title)) {
            throw new IllegalArgumentException("Invalid bookmark record");
        }
        StringBuilder value = new StringBuilder("outline")
            .append('|').append(index)
            .append('|').append(parentIndex == null ? "-" : parentIndex)
            .append('|').append(isOpen ? '1' : '0')
            .append('|').append(bold ? '1' : '0')
            .append('|').append(italic ? '1' : '0');
        for (double component : color) {
            value.append('|').append(doubleBits(component));
        }
        value.append('|').append(sha256(title.getBytes(StandardCharsets.UTF_8)));
        if (sourcePageIndex == null) {
            if (virtualPageIndex != null || side != null || targetView != null
                || mode != null || operands != null) {
                throw new IllegalArgumentException(
                    "Invalid structural bookmark destination"
                );
            }
            return value.append("|-").toString();
        }
        if (sourcePageIndex.intValue() < 0
            || virtualPageIndex == null || virtualPageIndex.intValue() < 0
            || !("left".equals(side) || "right".equals(side))
            || !"fit-source-page".equals(targetView)
            || !"/FitR".equals(mode)
            || operands == null
            || operands.length != 4
            || hasNull(operands)) {
            throw new IllegalArgumentException("Invalid bookmark destination");
        }
        value.append('|').append(sourcePageIndex)
            .append('|').append(virtualPageIndex)
            .append('|').append(side)
            .append('|').append(targetView)
            .append('|').append(mode)
            .append('|').append(operands.length);
        for (Double operand : operands) {
            value.append('|').append(
                operand == null ? "null" : doubleBits(operand.doubleValue())
            );
        }
        return value.toString();
    }

    public static String digest(
        String[] records,
        boolean removeAdjacentPageLinks,
        int removedAdjacentPageLinkCount,
        int retainedLinkCount
    ) throws Exception {
        if (removedAdjacentPageLinkCount < 0 || retainedLinkCount < 0
            || (!removeAdjacentPageLinks
                && removedAdjacentPageLinkCount != 0)) {
            throw new IllegalArgumentException(
                "Invalid navigation configuration"
            );
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(DOMAIN.getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) '\n');
        String configuration = "config|"
            + (removeAdjacentPageLinks ? "1" : "0")
            + "|" + removedAdjacentPageLinkCount
            + "|" + retainedLinkCount;
        digest.update(configuration.getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) '\n');
        for (String record : records) {
            digest.update(record.getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) '\n');
        }
        return toHex(digest.digest());
    }

    private static boolean finite(double[] values) {
        for (double value : values) {
            if (!Double.isFinite(value)) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasNull(Double[] values) {
        for (Double value : values) {
            if (value == null) {
                return true;
            }
        }
        return false;
    }

    private static boolean unitColor(double[] values) {
        for (double value : values) {
            if (value < 0.0 || value > 1.0) {
                return false;
            }
        }
        return true;
    }

    private static boolean wellFormedUtf16(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                    || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    return false;
                }
                index++;
            } else if (Character.isLowSurrogate(character)) {
                return false;
            }
        }
        return true;
    }

    private static String doubleBits(double value) {
        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException("Non-finite bookmark number");
        }
        return String.format("%016x", Double.doubleToRawLongBits(value));
    }

    private static String sha256(byte[] bytes) throws Exception {
        return toHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            text.append(String.format("%02x", value & 0xff));
        }
        return text.toString();
    }
}
