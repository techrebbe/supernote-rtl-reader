package com.techrebbe.supernote.spreadprobe.v2;

import java.util.Objects;
import java.util.Properties;

/** Strict, side-effect-free interpretation of a per-document v2 opt-in. */
public final class NativeReaderV2Config {
    public static final String ENGINE_KEY = "nativeReaderEngine";
    public static final String ENGINE_VALUE = "native-reader-v2";

    public enum Sizing { FIT, NATIVE_FILL }

    public final boolean enabled;
    public final SpreadPairing.Direction direction;
    public final boolean coverSeparate;
    public final boolean showDivider;
    public final boolean showHeader;
    public final Sizing sizing;

    private NativeReaderV2Config(
        boolean enabled,
        SpreadPairing.Direction direction,
        boolean coverSeparate,
        boolean showDivider,
        boolean showHeader,
        Sizing sizing
    ) {
        this.enabled = enabled;
        this.direction = Objects.requireNonNull(direction, "direction");
        this.coverSeparate = coverSeparate;
        this.showDivider = showDivider;
        this.showHeader = showHeader;
        this.sizing = Objects.requireNonNull(sizing, "sizing");
    }

    /**
     * Returns {@code null} unless the marker explicitly selects v2. This keeps
     * legacy markers and ordinary PDFs behaviorally inert during migration.
     */
    public static NativeReaderV2Config from(Properties properties) {
        Objects.requireNonNull(properties, "properties");
        if (!ENGINE_VALUE.equals(properties.getProperty(ENGINE_KEY))) {
            return null;
        }
        boolean enabled = strictBoolean(properties, "enabled", false);
        String directionValue = properties.getProperty("direction", "rtl");
        SpreadPairing.Direction direction;
        if ("rtl".equals(directionValue)) {
            direction = SpreadPairing.Direction.RTL;
        } else if ("ltr".equals(directionValue)) {
            direction = SpreadPairing.Direction.LTR;
        } else {
            throw new IllegalArgumentException("invalid reading direction");
        }
        String sizingValue = properties.getProperty("spreadSizing", "fit");
        Sizing sizing;
        if ("fit".equals(sizingValue)) {
            sizing = Sizing.FIT;
        } else if ("native_fill".equals(sizingValue)) {
            sizing = Sizing.NATIVE_FILL;
        } else {
            throw new IllegalArgumentException("invalid spread sizing");
        }
        return new NativeReaderV2Config(
            enabled,
            direction,
            strictBoolean(properties, "coverSeparate", false),
            strictBoolean(properties, "showDivider", false),
            strictBoolean(properties, "showHeader", false),
            sizing
        );
    }

    private static boolean strictBoolean(
        Properties properties,
        String key,
        boolean defaultValue
    ) {
        String fallback = defaultValue ? "true" : "false";
        String value = properties.getProperty(key, fallback);
        if ("true".equals(value)) return true;
        if ("false".equals(value)) return false;
        throw new IllegalArgumentException("invalid boolean for " + key);
    }
}
