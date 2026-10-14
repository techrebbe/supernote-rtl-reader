package com.techrebbe.rtl.pdfiumprobe;

public final class RenderBudgetTest {
    private static int assertions;
    private static void check(boolean value){assertions++;if(!value)throw new AssertionError("Check "+assertions);}
    private static void rejects(Runnable work){try{work.run();throw new AssertionError("Accepted invalid budget");}catch(IllegalArgumentException expected){assertions++;}}
    public static void main(String[] args){
        // Observed Nomad300dpi; original fixture612x792, XYZ zoom1.25.
        // Match actual Android conversion order to avoid half-pixel rounding
        // changing1912.5 to1912.4999999999998 in this characterization.
        double pdfToPixel=(300.0/160.0)*96.0/72.0,scale=1.25*pdfToPixel;
        long old=1250L*1618*4,heap=128L*1024*1024;
        int[] result=RenderBudget.dimensions(612,792,scale,heap,old);
        check(result[0]==1913 && result[1]==2475);
        check((long)result[0]*result[1]==4734675);
        check((long)result[0]*result[1]>4000000); // reproduces prior hard stop
        check(RenderBudget.MAX_PIXELS==6000000);
        rejects(()->RenderBudget.dimensions(3000,2001,1,heap,0));
        rejects(()->RenderBudget.dimensions(612,792,scale,64L*1024*1024,old));
        rejects(()->RenderBudget.dimensions(612,792,scale,heap,heap/2));
        rejects(()->RenderBudget.dimensions(612,792,Double.POSITIVE_INFINITY,heap,0));
        rejects(()->RenderBudget.dimensions(612,792,Double.NaN,heap,0));
        rejects(()->RenderBudget.dimensions(612,792,Double.MAX_VALUE,heap,0));
        rejects(()->RenderBudget.dimensions(0,792,1,heap,0));
        rejects(()->RenderBudget.dimensions(612,792,-1,heap,0));
        rejects(()->RenderBudget.dimensions(612,792,1,heap,-1));
        check(RenderBudget.dimensions(612,792,0.0001,heap,0)[0]==1);
        System.out.println("Actual raster-budget helper: "+assertions+" assertions PASS");
    }
}
