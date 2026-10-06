package com.facebook.react.bridge;
import java.util.HashMap;
public final class Arguments {
    public static final class MapValue extends HashMap<String,Object> implements WritableMap {
        public void putInt(String key,int value) { put(key,value); }
        public void putDouble(String key,double value) { put(key,value); }
        public void putString(String key,String value) { put(key,value); }
        public void putBoolean(String key,boolean value) { put(key,value); }
    }
    public static WritableMap createMap() { return new MapValue(); }
}
