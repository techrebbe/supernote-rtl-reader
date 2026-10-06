package com.facebook.react.bridge;
public interface WritableMap {
    void putInt(String key, int value);
    void putDouble(String key, double value);
    void putString(String key, String value);
    void putBoolean(String key, boolean value);
}
