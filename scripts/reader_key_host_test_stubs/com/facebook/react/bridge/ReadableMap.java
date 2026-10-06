package com.facebook.react.bridge;
public interface ReadableMap {
    ReadableMapKeySetIterator keySetIterator();
    ReadableType getType(String key);
    String getString(String key);
    boolean getBoolean(String key);
    ReadableArray getArray(String key);
}
