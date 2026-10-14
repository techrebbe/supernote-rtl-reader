package com.techrebbe.rtl.pdfiumprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.List;

/** One-page disposable diagnostic, NOT integrated RTL Reader or annotation UI. */
public final class ProbeActivity extends Activity {
    private static final String SHA="7cf9de8fa7ed91f7746ac44f62aa63e0641f757f330cf7d83efec7584b213905";
    private volatile long session;
    private volatile long generation;
    private volatile boolean closed;
    private boolean busy=true,modal;
    private int page,count;
    private double absoluteScale;
    private final ArrayDeque<Integer> history=new ArrayDeque<>();
    private JSONArray outline;
    private TextView status;
    private Surface surface;
    private Button previous,next,smaller,larger,fit,bookmarks,select,copy,back;

    private Button button(LinearLayout row,String title,Runnable callback){
        Button b=new Button(this);b.setText(title);b.setOnClickListener(v->callback.run());row.addView(b);return b;
    }
    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(Color.WHITE);
        status=new TextView(this);status.setPadding(12,8,12,8);status.setText("PDFium disposable probe · loading");root.addView(status);
        LinearLayout row=new LinearLayout(this);root.addView(row);
        previous=button(row,"Previous",()->turn(-1));next=button(row,"Next",()->turn(1));
        smaller=button(row,"−",()->changeZoom(.8));larger=button(row,"+",()->changeZoom(1.25));
        fit=button(row,"Fit",()->{absoluteScale=0;request(null);});bookmarks=button(row,"Bookmarks",this::bookmarks);
        LinearLayout tools=new LinearLayout(this);root.addView(tools);
        back=button(tools,"Link back",()->{if(!busy && !modal && !history.isEmpty()){page=history.pop();absoluteScale=0;request(null);}});
        select=button(tools,"Text",()->{surface.selecting=!surface.selecting;surface.clearSelection();select.setText(surface.selecting?"Pan":"Text");});
        copy=button(tools,"Copy selection",()->{
            if(!closed && !modal && !busy && surface.ready && !surface.selected.isEmpty())((ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Disposable PDF text",surface.selected));
        });
        button(tools,"Close probe",this::finish);
        surface=new Surface(this);root.addView(surface,new LinearLayout.LayoutParams(-1,0,1));setContentView(root);controls();
        EngineQueue.execute(()->{
            try{
                ByteArrayOutputStream data=new ByteArrayOutputStream();
                try(InputStream input=getAssets().open("fixture.pdf")){byte[] block=new byte[8192];int n;while((n=input.read(block))!=-1){if(data.size()+n>=1000000)throw new IllegalStateException("Fixture size bound");data.write(block,0,n);}}
                byte[] bytes=data.toByteArray();StringBuilder hex=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))hex.append(String.format("%02x",b&255));
                if(!SHA.equals(hex.toString()))throw new IllegalStateException("Embedded fixture identity mismatch");
                long opened=NativeCore.open(bytes);session=opened;int pages=NativeCore.count(opened);JSONArray tree=new JSONArray(NativeCore.outline(opened));
                runOnUiThread(()->{if(closed)return;count=pages;outline=tree;busy=false;surface.post(()->request(null));});
            }catch(Exception|LinkageError error){runOnUiThread(()->failure("Engine initialization failed"));}
        });
    }
    private void controls(){
        boolean ready=!closed && !busy && !modal && surface!=null && surface.ready;
        previous.setEnabled(ready && page>0);next.setEnabled(ready && page<count-1);
        smaller.setEnabled(ready);larger.setEnabled(ready);bookmarks.setEnabled(ready && outline!=null);
        select.setEnabled(ready);copy.setEnabled(ready && !surface.selected.isEmpty());fit.setEnabled(!closed && !busy && !modal && session>0);
        back.setEnabled(ready && !history.isEmpty());
    }
    private void failure(String reason){if(closed)return;busy=false;surface.ready=false;status.setText("STOP · "+reason+" · no document writes");controls();}
    private void turn(int delta){if(busy || modal || !surface.ready)return;page=Math.max(0,Math.min(count-1,page+delta));absoluteScale=0;request(null);}
    private void changeZoom(double factor){if(busy || modal || !surface.ready)return;try{absoluteScale=surface.model.getInt("renderWidth")/surface.model.getDouble("width")*factor;request(null);}catch(Exception error){failure("Zoom model rejected");}}
    private void request(JSONObject destination){
        if(closed || session<=0 || surface.getWidth()<=0 || surface.getHeight()<=0)return;
        final long ticket=++generation,owner=session;final int index=page,viewW=surface.getWidth(),viewH=surface.getHeight();final double requestedScale=absoluteScale;
        final JSONObject prior=surface.model;final double priorX=-surface.x,priorY=-surface.y;
        final double pdfToPixel=getResources().getDisplayMetrics().density*96.0/72.0;
        busy=true;surface.ready=false;surface.cancelContact();surface.clearSelection();status.setText("Rendering original page "+(index+1)+" · generation "+ticket);controls();
        EngineQueue.execute(()->{
            Bitmap bitmap=null;
            try{
                if(closed || ticket!=generation || session!=owner)return;
                double[] size=NativeCore.size(owner,index);double scale=requestedScale>0?requestedScale:Math.min((viewW-24)/size[0],(viewH-24)/size[1]);
                boolean xyz=destination!=null && destination.getString("mode").equals("XYZ");double[] anchor=null;
                if(xyz){
                    if(prior==null || prior.getLong("session")!=owner)throw new IllegalStateException("No settled destination source");
                    double[] location=NativeCore.point(owner,prior.getInt("pageIndex"),prior.getInt("renderWidth"),prior.getInt("renderHeight"),priorX,priorY,true);
                    double z=destination.isNull("zoom")?0:destination.getDouble("zoom");
                    scale=z>0?z*pdfToPixel:prior.getInt("renderWidth")/prior.getDouble("width");
                    anchor=new double[]{destination.isNull("left")?location[0]:destination.getDouble("left"),destination.isNull("top")?location[1]:destination.getDouble("top")};
                }
                if(!Double.isFinite(scale)||scale<=0)throw new IllegalStateException("Invalid scale");
                int w=Math.max(1,(int)Math.round(size[0]*scale)),h=Math.max(1,(int)Math.round(size[1]*scale));
                if((long)w*h>4000000)throw new IllegalStateException("Zoom budget");
                JSONObject model=new JSONObject(NativeCore.model(owner,index,w,h));
                if(model.getLong("session")!=owner || model.getInt("pageIndex")!=index || model.getInt("renderWidth")!=w || model.getInt("renderHeight")!=h)throw new IllegalStateException("Native model identity mismatch");
                if(closed || ticket!=generation || session!=owner)return;
                int[] pixels=NativeCore.render(owner,index,w,h);if(pixels.length!=(long)w*h)throw new IllegalStateException("Native bitmap length mismatch");
                if(closed || ticket!=generation || session!=owner)return;
                bitmap=Bitmap.createBitmap(pixels,w,h,Bitmap.Config.ARGB_8888);
                final Bitmap done=bitmap;
                final double[] mapped=anchor==null?null:NativeCore.point(owner,index,w,h,anchor[0],anchor[1],false);
                final double appliedScale=xyz||requestedScale>0?scale:0;
                runOnUiThread(()->{
                    if(closed || ticket!=generation || session!=owner){done.recycle();return;}
                    try{
                        surface.install(done,model,mapped);absoluteScale=appliedScale;busy=false;
                        status.setText("READY · source page "+(index+1)+" / "+count+" · PDFium157.0.8100.0 · disposable only");controls();
                    }catch(Exception error){done.recycle();failure("Native model rejected");}
                });
            }catch(Exception|LinkageError error){if(bitmap!=null)bitmap.recycle();runOnUiThread(()->{if(!closed && ticket==generation && session==owner)failure("Rendering failed (use Fit or Close)");});}
        });
    }
    private void follow(JSONObject action){
        if(busy || modal || !surface.ready)return;
        try{
            String kind=action.getString("kind");
            if(!kind.equals("internal")){modal=true;surface.cancelContact();controls();AlertDialog dialog=new AlertDialog.Builder(this).setMessage("Unsupported/external action blocked in this diagnostic").setPositiveButton("OK",null).create();dialog.setOnDismissListener(d->{modal=false;controls();});dialog.show();return;}
            int target=action.getInt("pageIndex");if(target<0 || target>=count)throw new IllegalStateException("Target page bound");
            String mode=action.getString("mode");if(!mode.equals("Fit") && !mode.equals("XYZ"))throw new IllegalStateException("Destination mode");
            history.push(page);while(history.size()>32)history.removeLast();page=target;
            if(mode.equals("Fit"))absoluteScale=0;request(action);
        }catch(Exception error){failure("Unsupported destination");}
    }
    private void bookmarks(){
        if(busy || modal || !surface.ready || outline==null)return;
        try{
            List<String> labels=new ArrayList<>();List<JSONObject> actions=new ArrayList<>();flatten(outline,"",labels,actions);
            modal=true;surface.cancelContact();controls();
            AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Original PDF bookmarks").setItems(labels.toArray(new String[0]),(d,which)->{modal=false;follow(actions.get(which));}).setNegativeButton("Cancel",null).create();
            dialog.setOnDismissListener(d->{modal=false;controls();});dialog.show();
        }catch(Exception error){failure("Invalid outline");}
    }
    private void flatten(JSONArray tree,String indent,List<String> labels,List<JSONObject> actions)throws Exception{
        if(indent.length()>64 || labels.size()>1000)throw new IllegalStateException("Outline bound");
        for(int i=0;i<tree.length();i++){JSONObject node=tree.getJSONObject(i);labels.add(indent+node.getString("title"));actions.add(node.getJSONObject("destination"));flatten(node.getJSONArray("children"),indent+"  ",labels,actions);}
    }
    @Override public void onDestroy(){
        closed=true;++generation;if(surface!=null){surface.ready=false;surface.release();}
        EngineQueue.execute(()->{long owner=session;session=0;if(owner>0)NativeCore.close(owner);});super.onDestroy();
    }
    final class Surface extends View {
        Bitmap bitmap;JSONObject model;boolean ready,selecting,pressed,dragged;float x,y,lastX,lastY,downX,downY;int start=-1,end=-1;String selected="";final Paint paint=new Paint();
        Surface(Context context){super(context);setFocusable(false);}
        void release(){if(bitmap!=null){bitmap.recycle();bitmap=null;}model=null;selected="";}
        void clearSelection(){start=end=-1;selected="";invalidate();}
        void cancelContact(){pressed=false;dragged=false;}
        void install(Bitmap image,JSONObject data,double[] anchor)throws Exception{
            release();bitmap=image;model=data;x=Math.max(12,(getWidth()-image.getWidth())/2f);y=Math.max(12,(getHeight()-image.getHeight())/2f);
            if(anchor!=null){x=-(float)anchor[0];y=-(float)anchor[1];}
            ready=true;cancelContact();clearSelection();invalidate();
        }
        @Override protected void onSizeChanged(int w,int h,int oldW,int oldH){super.onSizeChanged(w,h,oldW,oldH);if(session>0 && !closed)post(()->request(null));}
        @Override protected void onDraw(Canvas canvas){super.onDraw(canvas);canvas.drawColor(Color.LTGRAY);if(bitmap==null)return;paint.setColor(Color.BLACK);canvas.drawBitmap(bitmap,x,y,paint);
            if(start<0 || end<0 || model==null)return;paint.setColor(0x604060e0);int clip=canvas.save();canvas.clipRect(x,y,x+bitmap.getWidth(),y+bitmap.getHeight());
            try{JSONArray chars=model.getJSONArray("chars");for(int i=Math.min(start,end);i<=Math.max(start,end);i++){JSONArray r=chars.getJSONObject(i).getJSONArray("rect");canvas.drawRect((float)r.getDouble(0)+x,(float)r.getDouble(1)+y,(float)r.getDouble(2)+x,(float)r.getDouble(3)+y,paint);}}catch(Exception ignored){selected="";}finally{canvas.restoreToCount(clip);}
        }
        int charAt(float px,float py)throws Exception{if(bitmap==null || !Interaction.inside(px,py,bitmap.getWidth(),bitmap.getHeight()))return -1;JSONArray chars=model.getJSONArray("chars");for(int i=0;i<chars.length();i++){JSONArray r=chars.getJSONObject(i).getJSONArray("rect");if(px>=r.getDouble(0)&&px<=r.getDouble(2)&&py>=r.getDouble(1)&&py<=r.getDouble(3))return i;}return -1;}
        @Override public boolean onTouchEvent(MotionEvent event){
            if(!ready || busy || modal || closed || model==null || event.getPointerCount()!=1){cancelContact();return true;}
            float px=event.getX()-x,py=event.getY()-y;
            try{
                if(event.getAction()==MotionEvent.ACTION_DOWN){pressed=true;dragged=false;downX=lastX=event.getX();downY=lastY=event.getY();if(selecting){start=end=charAt(px,py);selected="";}return true;}
                if(!pressed)return true;
                if(event.getAction()==MotionEvent.ACTION_MOVE){dragged=Interaction.dragged(dragged,downX,downY,event.getX(),event.getY());if(selecting && start>=0){int hit=charAt(px,py);if(hit>=0)end=hit;invalidate();}else if(!selecting){x+=event.getX()-lastX;y+=event.getY()-lastY;lastX=event.getX();lastY=event.getY();invalidate();}return true;}
                if(event.getAction()==MotionEvent.ACTION_UP){
                    dragged=Interaction.dragged(dragged,downX,downY,event.getX(),event.getY());
                    if(selecting && start>=0 && end>=0){JSONArray chars=model.getJSONArray("chars");int[] starts=new int[chars.length()],ends=new int[chars.length()];String[] gaps=new String[chars.length()];for(int i=0;i<chars.length();i++){JSONObject ch=chars.getJSONObject(i);starts[i]=ch.getInt("textStart");ends[i]=ch.getInt("textEnd");gaps[i]=ch.getString("gapBefore");}selected=Interaction.copy(model.getString("text"),starts,ends,gaps,Math.min(start,end),Math.max(start,end));status.setText("Selected disposable text: "+selected);controls();}
                    else if(!selecting && !dragged && bitmap!=null && Interaction.inside(px,py,bitmap.getWidth(),bitmap.getHeight())){JSONArray links=model.getJSONArray("links");for(int i=0;i<links.length();i++){JSONObject link=links.getJSONObject(i);JSONArray r=link.getJSONArray("rect");if(px>=r.getDouble(0)&&px<=r.getDouble(2)&&py>=r.getDouble(1)&&py<=r.getDouble(3)){follow(link.getJSONObject("action"));break;}}}
                    cancelContact();
                    return true;
                }
                if(event.getAction()==MotionEvent.ACTION_CANCEL){cancelContact();clearSelection();controls();return true;}
            }catch(Exception error){failure("Hit-test metadata rejected");}
            return true;
        }
    }
}
