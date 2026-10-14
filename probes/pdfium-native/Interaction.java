package com.techrebbe.rtl.pdfiumprobe;

/** Small production-used rules also executable with the host JDK. */
final class Interaction {
    static boolean dragged(boolean previous,float downX,float downY,float x,float y){
        return previous || Math.abs(x-downX)>=8 || Math.abs(y-downY)>=8;
    }
    static boolean inside(float x,float y,int width,int height){
        return Float.isFinite(x) && Float.isFinite(y) && x>=0 && y>=0 && x<width && y<height;
    }
    static String copy(String text,int[] starts,int[] ends,String[] gaps,int first,int last){
        if(starts.length!=ends.length || starts.length!=gaps.length || first<0 || last<first || last>=starts.length)throw new IllegalArgumentException("Selection bounds");
        StringBuilder out=new StringBuilder();
        for(int i=first;i<=last;i++){
            if(starts[i]<0 || ends[i]<starts[i] || ends[i]>text.length())throw new IllegalArgumentException("Text bounds");
            if(i>first){
                // Only native-authorized generated/missing-box separators,
                // never a substring spanning CropBox-excluded source text.
                for(int j=0;j<gaps[i].length();j++)if(" \t\r\n".indexOf(gaps[i].charAt(j))<0)throw new IllegalArgumentException("Non-separator gap");
                out.append(gaps[i]);
            }
            out.append(text,starts[i],ends[i]);
        }
        return out.toString();
    }
    private Interaction(){}
}
