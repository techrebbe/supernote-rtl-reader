package com.techrebbe.rtl.pdfiumprobe;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Actual production helpers, not copied gesture/queue implementations. */
public final class InteractionTest {
    private static int assertions;
    private static void check(boolean result){assertions++;if(!result)throw new AssertionError("Check "+assertions);}
    public static void main(String[] args)throws Exception{
        check(!Interaction.dragged(false,0,0,3,0));
        check(Interaction.dragged(false,0,0,123,0)); // distant UP, no MOVE
        check(Interaction.dragged(Interaction.dragged(false,0,0,3,0),0,0,123,0));
        check(Interaction.dragged(true,0,0,0,0)); // return to down cannot reset
        check(!Interaction.inside(-1,0,100,100));check(!Interaction.inside(0,100,100,100));
        check(!Interaction.inside(Float.NaN,0,100,100));check(Interaction.inside(0,0,100,100));
        check(Interaction.copy("A\r\nB",new int[]{0,3},new int[]{1,4},new String[]{"","\r\n"},0,1).equals("A\r\nB"));
        check(Interaction.copy("AhiddenB",new int[]{0,7},new int[]{1,8},new String[]{"",""},0,1).equals("AB"));
        check(Interaction.copy("A\ud83d\ude00B",new int[]{0,1,3},new int[]{1,3,4},new String[]{"","",""},0,2).equals("A\ud83d\ude00B"));
        check(Interaction.copy("A\r\nB",new int[]{0,3},new int[]{1,4},new String[]{"","\r\n"},1,1).equals("B"));
        try{Interaction.copy("AB",new int[]{0,1},new int[]{1,2},new String[]{"","hidden"},0,1);throw new AssertionError("Hidden gap accepted");}catch(IllegalArgumentException expected){assertions++;}
        List<String> trace=new ArrayList<>();CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),done=new CountDownLatch(1);
        EngineQueue.execute(()->{try{entered.countDown();release.await();trace.add("old render");}catch(InterruptedException error){throw new AssertionError(error);}});
        check(entered.await(5,TimeUnit.SECONDS));
        EngineQueue.execute(()->trace.add("old close"));EngineQueue.execute(()->{trace.add("new open");done.countDown();});release.countDown();
        check(done.await(5,TimeUnit.SECONDS));check(trace.toString().equals("[old render, old close, new open]"));
        System.out.println("Actual interaction/ownership helpers: "+assertions+" assertions PASS");
        System.exit(0); // process-global production executor intentionally lives until process exit
    }
}
