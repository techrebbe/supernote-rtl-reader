package com.techrebbe.rtl.pdfiumprobe;

// Package-private disposable engine bridge, not production ReaderKeyHost/SDK.
final class NativeCore {
    static { System.loadLibrary("pdfium"); System.loadLibrary("rtlpdfiumprobe"); }
    static native long open(byte[] fixture);
    static native int count(long session);
    static native String outline(long session);
    static native double[] size(long session, int pageIndex);
    static native double[] point(long session, int pageIndex, int width, int height, double x, double y, boolean inverse);
    static native String model(long session, int pageIndex, int width, int height);
    static native int[] render(long session, int pageIndex, int width, int height);
    static native void close(long session);
    private NativeCore() {}
}
