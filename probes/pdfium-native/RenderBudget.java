package com.techrebbe.rtl.pdfiumprobe;

/** Diagnostic-only bounded full-page raster, not the future production tiler. */
final class RenderBudget {
    static final int MAX_PIXELS=6000000;
    static final long MODEL_RESERVE=2L*1024*1024;
    static final class Exceeded extends IllegalArgumentException {
        private static final long serialVersionUID=1L;
        Exceeded(){super("Requested zoom exceeds the bounded bitmap budget");}
    }
    static int[] dimensions(double width,double height,double scale,long maxHeap,long oldBitmapBytes){
        if(!Double.isFinite(width)||!Double.isFinite(height)||!Double.isFinite(scale)
                ||width<=0||height<=0||width>20000||height>20000||scale<=0
                ||maxHeap<=0||oldBitmapBytes<0)throw new IllegalArgumentException("Invalid render geometry");
        double scaledW=width*scale,scaledH=height*scale;
        if(!Double.isFinite(scaledW)||!Double.isFinite(scaledH)||scaledW>MAX_PIXELS||scaledH>MAX_PIXELS)throw new Exceeded();
        long w=Math.max(1,Math.round(scaledW)),h=Math.max(1,Math.round(scaledH)),pixels=w*h;
        // New int[] and new bitmap, plus retained old bitmap and metadata.
        // Reserve at least half the Java heap for unrelated/engine overhead.
        // Native allocation is additionally capped at MAX_PIXELS (6M); this is
        // conservative arithmetic, not an empirical memory/leak guarantee.
        if(pixels>MAX_PIXELS || oldBitmapBytes>maxHeap/2
                ||pixels*8+MODEL_RESERVE>maxHeap/2-oldBitmapBytes)throw new Exceeded();
        return new int[]{(int)w,(int)h};
    }
    private RenderBudget(){}
}
