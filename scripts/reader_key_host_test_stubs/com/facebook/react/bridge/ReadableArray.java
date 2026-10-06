package com.facebook.react.bridge;
public interface ReadableArray {
    int size();
    ReadableType getType(int index);
    double getDouble(int index);
    String getString(int index);
}
