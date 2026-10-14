package com.techrebbe.rtl.pdfiumprobe;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native ownership is process-global; open/read/close must share one FIFO. */
final class EngineQueue {
    private static final ExecutorService QUEUE=Executors.newSingleThreadExecutor();
    static void execute(Runnable work){QUEUE.execute(work);}
    // Activity destruction queues close, but cannot shut down another owner's
    // process queue. Android process exit releases the executor itself.
    private EngineQueue(){}
}
