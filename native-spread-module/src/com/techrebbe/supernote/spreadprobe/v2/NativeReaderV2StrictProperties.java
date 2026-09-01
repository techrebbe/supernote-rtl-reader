package com.techrebbe.supernote.spreadprobe.v2;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/** Java-properties decoding that rejects duplicate logical keys. */
public final class NativeReaderV2StrictProperties {
    public static final int MAX_BYTES = 128 * 1024;

    private NativeReaderV2StrictProperties() {}

    public static Properties parse(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_BYTES) {
            throw new IllegalArgumentException("invalid marker byte length");
        }
        for (byte item : bytes) {
            if (item == 0) {
                throw new IllegalArgumentException("marker contains NUL");
            }
        }
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        Set<String> keys = new HashSet<>();
        StringBuilder logical = new StringBuilder();
        boolean continuing = false;
        int start = 0;
        for (int index = 0; index <= text.length(); index++) {
            if (index != text.length() && text.charAt(index) != '\n'
                && text.charAt(index) != '\r') {
                continue;
            }
            String physical = text.substring(start, index);
            if (index < text.length() && text.charAt(index) == '\r'
                && index + 1 < text.length()
                && text.charAt(index + 1) == '\n') {
                index++;
            }
            start = index + 1;
            if (continuing) {
                physical = stripLeadingPropertyWhitespace(physical);
            }
            logical.append(physical);
            if (endsWithContinuation(logical)) {
                logical.setLength(logical.length() - 1);
                continuing = true;
                continue;
            }
            continuing = false;
            inspectLogicalLine(logical.toString(), keys);
            logical.setLength(0);
        }
        if (continuing) {
            throw new IllegalArgumentException("unterminated marker continuation");
        }
        Properties properties = load(bytes);
        if (properties.size() != keys.size()) {
            throw new IllegalArgumentException("marker key decoding was ambiguous");
        }
        return properties;
    }

    private static void inspectLogicalLine(String line, Set<String> keys) {
        int first = 0;
        while (first < line.length() && isPropertyWhitespace(line.charAt(first))) {
            first++;
        }
        if (first == line.length() || line.charAt(first) == '#'
            || line.charAt(first) == '!') {
            return;
        }
        Properties one = load(
            (line + "\n").getBytes(StandardCharsets.ISO_8859_1)
        );
        if (one.size() != 1) {
            throw new IllegalArgumentException("invalid marker property line");
        }
        String key = one.stringPropertyNames().iterator().next();
        if (!keys.add(key)) {
            throw new IllegalArgumentException("duplicate marker key " + key);
        }
    }

    private static Properties load(byte[] bytes) {
        Properties properties = new Properties();
        try {
            properties.load(new ByteArrayInputStream(bytes));
            return properties;
        } catch (IOException | IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                "invalid Java properties marker",
                exception
            );
        }
    }

    private static boolean endsWithContinuation(StringBuilder line) {
        int slashes = 0;
        for (int index = line.length() - 1;
            index >= 0 && line.charAt(index) == '\\'; index--) {
            slashes++;
        }
        return (slashes & 1) != 0;
    }

    private static String stripLeadingPropertyWhitespace(String value) {
        int index = 0;
        while (index < value.length()
            && isPropertyWhitespace(value.charAt(index))) {
            index++;
        }
        return value.substring(index);
    }

    private static boolean isPropertyWhitespace(char value) {
        return value == ' ' || value == '\t' || value == '\f';
    }
}
