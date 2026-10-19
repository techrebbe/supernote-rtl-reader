"""Concrete generated-App integration, actual ledger and source regression gates."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from patch_pdfium_reader import patch_app, patch_index

ROOT=Path(__file__).resolve().parent.parent


def generated(output):
    app=output/'App.js';index=output/'index.js'
    app.write_text((ROOT/'overlay/App.js').read_text(encoding='utf-8').replace(
        '<View style={styles.footer}>',"<View style={[styles.footer, {direction: 'ltr'}]}>"),encoding='utf-8')
    index.write_text((ROOT/'overlay/index.js').read_text(encoding='utf-8'),encoding='utf-8')
    subprocess.run([sys.executable,str(ROOT/'scripts/patch_direct_view.py'),str(app)],check=True)
    # Same direction-only prefetch transform used by install_native.py.
    spec=importlib.util.spec_from_file_location('canonical_installer',ROOT/'scripts/install_native.py')
    installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
    installer.patch_app_prefetch_direction(app)
    subprocess.run([sys.executable,str(ROOT/'scripts/patch_initial_layout.py'),str(app)],check=True)
    a=patch_app(app.read_text(encoding='utf-8'));b=patch_index(index.read_text(encoding='utf-8'))
    app.write_text(a,encoding='utf-8');index.write_text(b,encoding='utf-8')
    return a,b


class Integration(unittest.TestCase):
    def test_actual_native_touch_sequences(self):
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    private static float bound(')
        touch=source[begin:source.index('    private void follow(',begin)].replace('@Override ','')
        harness=r'''package test;
import java.util.*;
class MotionEvent {
 static final int ACTION_DOWN=0,ACTION_UP=1,ACTION_MOVE=2,ACTION_CANCEL=3,ACTION_POINTER_DOWN=5,ACTION_POINTER_UP=6;
 final int action;final int[] ids;final float[] xs,ys;
 MotionEvent(int a,int[] ids,float[] xs,float[] ys){action=a;this.ids=ids;this.xs=xs;this.ys=ys;}
 int getActionMasked(){return action;}int getPointerCount(){return ids.length;}
 int getPointerId(int i){return ids[i];}int findPointerIndex(int id){for(int i=0;i<ids.length;i++)if(ids[i]==id)return i;return -1;}
 float getX(){return getX(0);}float getY(){return getY(0);}float getX(int i){return xs[i];}float getY(int i){return ys[i];}
}
class JSONObject {
 String mode="read";long epoch;boolean blocked,inputBlocked;
 String getString(String k){return k.equals("mode")?mode:k.equals("sessionId")?"11":"";}
 String optString(String k){return getString(k);}long optLong(String k,long d){return epoch;}
 boolean optBoolean(String k,boolean d){return k.equals("blocked")?blocked:inputBlocked;}
 JSONArray getJSONArray(String k){return new JSONArray();}int getInt(String k){return 0;}
 JSONObject getJSONObject(String k){return this;}
}
class JSONArray {int length(){return 0;}JSONObject getJSONObject(int i){return new JSONObject();}double getDouble(int i){return 0;}}
class Bitmap {int getWidth(){return 600;}int getHeight(){return 800;}}
class WritableMap extends HashMap<String,Object>{void putDouble(String k,double v){put(k,v);}void putString(String k,String v){put(k,v);}}
class PdfiumSession {static boolean available=true;static void require(String id)throws Exception{if(!available)throw new Exception("gone");}}
class ActualPage {
 boolean disposed,ready=true,pressed,dragged,multiTouch,pinching;int pinchA,pinchB,start=-1,end=-1;
 long revision=8,touchSequence,pinchRevision,pinchEpoch;float x,y,lastX,lastY,downX,downY;
 float pinchDistance,pinchFactor,pinchSourceX,pinchSourceY,pinchFocusX,pinchFocusY;String selected="";
 JSONObject request=new JSONObject(),model=new JSONObject();Bitmap bitmap=new Bitmap();
 int pinches,gestures,links,anchors,failures;float[] result;
 int getWidth(){return 600;}int getHeight(){return 800;}void invalidate(){}
 int charAt(float a,float b){return -1;}void fail(long t,String m){failures++;}
 WritableMap packet(String k){WritableMap m=new WritableMap();m.putString("kind",k);return m;}
 void emit(WritableMap m){if(m.get("kind").equals("gesture"))gestures++;}
 void follow(JSONObject j){links++;}void sendAnchor(){anchors++;}
 void sendPinch(float f,float sx,float sy,float fx,float fy){pinches++;result=new float[]{f,sx,sy,fx,fy};}
 /*ACTUAL_TOUCH*/
}
public class TouchTest {
 static int assertions;static void ok(boolean b,String message){if(!b)throw new AssertionError(message);assertions++;}
 static void one(ActualPage p,int a,float x,float y){p.onTouchEvent(new MotionEvent(a,new int[]{5},new float[]{x},new float[]{y}));}
 static void two(ActualPage p,int a,float bx){p.onTouchEvent(new MotionEvent(a,new int[]{5,9},new float[]{100,bx},new float[]{200,200}));}
 static ActualPage begin(){ActualPage p=new ActualPage();one(p,0,100,200);two(p,5,300);return p;}
 static void end(ActualPage p){two(p,6,350);one(p,1,100,200);}
 public static void main(String[] args){
  ActualPage tap=new ActualPage();one(tap,0,100,200);one(tap,1,100,200);ok(tap.gestures==1&&tap.pinches==0,"single tap unchanged");
  ActualPage swipe=new ActualPage();one(swipe,0,100,200);one(swipe,2,300,200);one(swipe,1,300,200);ok(swipe.gestures==1&&swipe.pinches==0,"single swipe unchanged");
  ActualPage p=begin();two(p,2,350);ok(p.pinches==0,"MOVE never rerasterizes");end(p);
  ok(p.pinches==1&&p.gestures==0&&p.links==0,"one pinch, never two taps/links");
  ok(p.result[0]==1.25f&&p.result[1]==200&&p.result[2]==200&&p.result[3]==225&&p.result[4]==200,"source anchor and final focus captured");
  one(p,0,100,200);one(p,1,100,200);ok(p.gestures==1,"new single contact allowed after pinch ends");
  p=begin();two(p,6,300);one(p,1,100,200);ok(p.pinches==0&&p.gestures==0,"two-finger tap suppressed");
  p=begin();two(p,2,350);one(p,3,100,200);end(p);ok(p.pinches==0&&p.gestures==0,"cancel suppresses pinch and trailing UP");
  p=begin();p.onTouchEvent(new MotionEvent(5,new int[]{5,9,12},new float[]{100,350,400},new float[]{200,200,200}));end(p);
  ok(p.pinches==0&&p.gestures==0,"third pointer cancels whole contact");
  p=begin();p.onTouchEvent(new MotionEvent(2,new int[]{9,5},new float[]{350,100},new float[]{200,200}));end(p);
  ok(p.pinches==1&&p.result[0]==1.25f,"pointer indices may reorder; IDs own contact");
  for(String change:new String[]{"revision","epoch","blocked","input","notready","disposed","session","missing","nonfinite"}){
   p=begin();two(p,2,350);
   switch(change){case "revision":p.revision++;break;case "epoch":p.request.epoch++;break;
    case "blocked":p.request.blocked=true;break;case "input":p.request.inputBlocked=true;break;
    case "notready":p.ready=false;break;case "disposed":p.disposed=true;break;case "session":PdfiumSession.available=false;break;
    case "missing":p.onTouchEvent(new MotionEvent(2,new int[]{5,10},new float[]{100,350},new float[]{200,200}));break;
    case "nonfinite":two(p,2,Float.NaN);break;}
   end(p);ok(p.pinches==0&&p.gestures==0,"reject "+change);PdfiumSession.available=true;
  }
  p=new ActualPage();p.request.mode="text";one(p,0,100,200);two(p,5,300);end(p);ok(p.pinches==0&&p.gestures==0,"Text mode cannot pinch");
  p=begin();two(p,2,2000);two(p,6,2000);one(p,1,100,200);
  ok(p.pinches==1&&p.result[0]==2&&p.result[3]==600,"gesture factor/focus bounded even across sibling");
  p=begin();two(p,2,120);two(p,6,120);one(p,1,100,200);ok(p.result[0]==.5f,"inward factor bounded");
  System.out.println(assertions+" actual native touch/pointer/cancel assertions PASS (controlled MotionEvent, not hardware)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-touch-') as temp:
            root=Path(temp);java=root/'TouchTest.java'
            (root/'Interaction.java').write_text((ROOT/'probes/pdfium-native/Interaction.java').read_text().replace(
                'package com.techrebbe.rtl.pdfiumprobe;','package test;'),encoding='utf-8')
            java.write_text(harness.replace('/*ACTUAL_TOUCH*/',touch),encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(root/'Interaction.java'),str(java)],check=True)
            result=subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.TouchTest'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);print(result.stdout.strip())

    def test_actual_pinch_async_anchor_and_fences(self):
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    private void sendPinch(')
        pinch=source[begin:source.index('    private void sendAnchor()',begin)]
        begin=source.index('    private boolean current(')
        current=source[begin:source.index('    private void schedule()',begin)]
        harness=r'''package test;
import java.util.*;
class JSONObject {
 long epoch;boolean inputBlocked;
 String optString(String k){return k.equals("sessionId")?"11":k.equals("slot")?"single":"stamp";}
 long optLong(String k,long d){return epoch;}boolean optBoolean(String k,boolean d){return inputBlocked;}
 int getInt(String k){return k.equals("pageIndex")?1:k.equals("renderWidth")?600:800;}
}
class WritableMap extends HashMap<String,Object>{void putDouble(String k,double v){put(k,v);}void putString(String k,String v){put(k,v);}}
class Queue {final Deque<Runnable> work=new ArrayDeque<>();void execute(Runnable r){work.add(r);}void drain(){while(!work.isEmpty())work.remove().run();}}
class PdfiumSession {
 static Queue QUEUE=new Queue();static final PdfiumSession SESSION=new PdfiumSession();long token=11;boolean alive=true;
 static PdfiumSession require(String id){return SESSION;}boolean current(){return alive;}
}
class PdfiumReaderCore {
 static boolean rotated,broken;static int pointCalls;
 static double[] size(long id,int page){return new double[]{600,800};}
 // Controlled invertible CropBox/rotation peers. Actual JNI/PDFium geometry
 // remains separately gated; this checks the production composition/order.
 static double[] point(long id,int page,int w,int h,double x,double y,boolean inverse){
  pointCalls++;if(broken)throw new IllegalArgumentException("geometry");
  if(inverse){double u=x/w,v=y/h;return rotated?new double[]{20+600*v,30+800*u}:new double[]{20+600*u,30+800*(1-v)};}
  double u=rotated?(y-30)/800:(x-20)/600,v=rotated?(x-20)/600:1-(y-30)/800;return new double[]{u*w,v*h};
 }
}
class ActualPage {
 JSONObject request=new JSONObject(),model=new JSONObject();long revision=8,touchSequence=3;
 boolean disposed,attached=true,failed,ready=true;int failures;final Queue ui=new Queue();final List<WritableMap> events=new ArrayList<>();
 int getWidth(){return 600;}int getHeight(){return 800;}void dispatch(Runnable r){ui.execute(r);}
 WritableMap packet(String k){WritableMap m=new WritableMap();m.putString("kind",k);return m;}
 void emit(WritableMap m){events.add(m);}void fail(long t,String m){if(!disposed&&revision==t&&!failed){failed=true;failures++;}}
 /*ACTUAL_CURRENT*/
 /*ACTUAL_PINCH*/
 void finish(){sendPinch(1.25f,200,200,225,200);}
}
public class PinchAsyncTest {
 static int assertions;static void ok(boolean b,String label){if(!b)throw new AssertionError(label);assertions++;}
 static double number(WritableMap p,String k){return ((Number)p.get(k)).doubleValue();}
 public static void main(String[] args){
  for(boolean rotation:new boolean[]{false,true}){
   PdfiumReaderCore.rotated=rotation;ActualPage p=new ActualPage();p.finish();
   ok(p.events.isEmpty()&&PdfiumSession.QUEUE.work.size()==1,"one read-only queue operation");
   PdfiumSession.QUEUE.drain();ok(p.events.isEmpty()&&p.ui.work.size()==1,"native result awaits UI admission");p.ui.drain();
   ok(p.events.size()==1&&p.events.get(0).get("kind").equals("pinch"),"one current pinch packet");
   WritableMap packet=p.events.get(0);ok(number(packet,"scale")==1.25,"scale from actual integer dimensions");
   double[] anchor=PdfiumReaderCore.point(11,1,600,800,200,200,true);
   double[] target=PdfiumReaderCore.point(11,1,750,1000,anchor[0],anchor[1],false);
   double[] origin=PdfiumReaderCore.point(11,1,750,1000,number(packet,"fromLeft"),number(packet,"fromTop"),false);
   ok(Math.abs(target[0]-origin[0]-225)<.001&&Math.abs(target[1]-origin[1]-200)<.001,"same original source point remains at final centroid, rotated="+rotation);
  }
  for(String race:new String[]{"ticket","epoch","newcontact","input","notready","disposed","detached","failed","session"}){
   ActualPage p=new ActualPage();p.finish();PdfiumSession.QUEUE.drain();
   switch(race){case "ticket":p.revision++;break;case "epoch":p.request.epoch++;break;case "newcontact":p.touchSequence++;break;
    case "input":p.request.inputBlocked=true;break;case "notready":p.ready=false;break;case "disposed":p.disposed=true;break;
    case "detached":p.attached=false;break;case "failed":p.failed=true;break;case "session":PdfiumSession.SESSION.alive=false;break;}
   p.ui.drain();ok(p.events.isEmpty(),"UI drops delayed pinch: "+race);PdfiumSession.SESSION.alive=true;
  }
  ActualPage p=new ActualPage();p.finish();p.revision++;int calls=PdfiumReaderCore.pointCalls;PdfiumSession.QUEUE.drain();p.ui.drain();
  ok(PdfiumReaderCore.pointCalls==calls&&p.events.isEmpty(),"stale queued request does no geometry work");
  PdfiumReaderCore.broken=true;p=new ActualPage();p.finish();PdfiumSession.QUEUE.drain();p.ui.drain();ok(p.failures==1,"current geometry failure uses existing terminal error path");
  p=new ActualPage();p.finish();PdfiumSession.QUEUE.drain();p.touchSequence++;p.ui.drain();ok(p.failures==0,"old contact failure cannot poison a new contact");
  PdfiumReaderCore.broken=false;
  System.out.println(assertions+" actual pinch queue/anchor/stale-contact assertions PASS (controlled peers)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-pinch-async-') as temp:
            root=Path(temp);java=root/'PinchAsyncTest.java'
            (root/'PdfiumViewport.java').write_text((ROOT/'native/PdfiumViewport.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (root/'RenderBudget.java').write_text((ROOT/'probes/pdfium-native/RenderBudget.java').read_text().replace(
                'package com.techrebbe.rtl.pdfiumprobe;','package test;'),encoding='utf-8')
            java.write_text(harness.replace('/*ACTUAL_CURRENT*/',current).replace('/*ACTUAL_PINCH*/',pinch),encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,
                str(root/'PdfiumViewport.java'),str(root/'RenderBudget.java'),str(java)],check=True)
            result=subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.PinchAsyncTest'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);print(result.stdout.strip())

    def test_real_generated_slots_and_guards(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-integrated-app-') as temp:
            app,index=generated(Path(temp))
            self.assertEqual(app.count('<InteractivePdfPage'),3)
            self.assertIn('export default function App({libraryTarget = null})',app)
            self.assertLess(app.index('assertLibraryContext(libraryTarget, context)'),app.index('await pdfium.open(context)'))
            self.assertLess(app.index('assertLibraryOwner(libraryTarget, openedPdf)'),app.index('const restored = decodePreferences('))
            self.assertIn('catch (error) { await pdfium.close(false); throw error; }',app)
            self.assertIn('<FavouriteButton owner={pdfium.owner}',app)
            self.assertIn('<ReaderLaunch key={activation} App={App}',index)
            self.assertIn('RTL_READER_LIBRARY_OPEN_IN_FLIGHT',index)
            subprocess.run(['node',str(ROOT/'scripts/test_reader_library_generated.js'),str(Path(temp)/'index.js')],check=True)
            build=(ROOT/'build.sh').read_text(encoding='utf-8')
            for name in ('readerLibrary','ReaderLaunch'):
                self.assertIn(f'cp "$ROOT/overlay/{name}.js" "$PROJECT/{name}.js"',build)
            native_build=(ROOT/'scripts/build_pdfium_reader.py').read_text(encoding='utf-8')
            self.assertIn('ReaderLibraryModule(reactContext)',native_build)
            from build_pdfium_reader import source_inputs,JAVA
            self.assertIn('ReaderLibraryModule',JAVA)
            for name in ('readerLibrary','ReaderLaunch'):
                self.assertIn(ROOT/f'overlay/{name}.js',source_inputs(ROOT))
            self.assertEqual(app.count('<PdfiumTouchHost style={styles.spread}>'),1)
            self.assertEqual(app.count('</PdfiumTouchHost>'),1)
            self.assertNotIn('<NativePdfPageView',app)
            self.assertEqual(app.count('blocked={Boolean(fatalError) || display.pdfiumRevision !== pdfium.revision}'),3)
            self.assertEqual(app.count('pdfiumRevision: pdfium.revision,'),2)
            for slot in ('single','left','right'):
                self.assertIn('key={`'+slot+':${display.renderToken}`}',app)
            host=app[app.index('      <ReaderKeyView'):app.index("        {display.kind === 'spread'",app.index('      <ReaderKeyView'))]
            self.assertNotIn('panResponderRef.current.panHandlers',host)
            self.assertEqual(app.count('<View style={styles.blankPage} {...panResponderRef.current.panHandlers} />'),2)
            for slot in ('single','left','right'):self.assertIn(f'slot="{slot}"',app)
            self.assertIn('pageAreaLayout.height,',app)
            self.assertIn('readerWindowLayout.width > readerWindowLayout.height',app)
            self.assertNotIn('? pageAreaLayout.width > pageAreaLayout.height',app)
            self.assertIn('const savedInkProfile = null;',app)
            self.assertIn('restoreSourcePreferences(rawPreferences, openedPdf.sourceSha256)',app)
            self.assertIn('pdfSourceSha256: pdfium.owner?.sourceSha256',app)
            self.assertIn('const nextLogicalPage = () => goBy(pageStep());',app)
            self.assertIn('const previousLogicalPage = () => goBy(-pageStep());',app)
            self.assertIn('turn={action => action',app)
            subprocess.run(['node',str(ROOT/'scripts/test_pdfium_generated_callbacks.js'),str(Path(temp)/'App.js')],check=True)
            self.assertIn('await pdfium.close(true);',app)
            self.assertLess(app.index("await savePreferences('edit', payload);"),app.index('await pdfium.close(true);'))
            self.assertLess(app.index('await pdfium.close(true);'),app.index('        await handoffSavedPage({'))
            self.assertIn('await pdfiumOwner.close(!pdfiumOwner.sourceInvalid.current)',index)
            # No changed private-config/native-restart implementation is introduced.
            self.assertEqual(app.count('        await handoffSavedPage({'),1)

    def test_patch_drift_fails_not_partial(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-integrated-drift-') as temp:
            app,index=generated(Path(temp))
            with self.assertRaises(ValueError):patch_app(app)
            with self.assertRaises(ValueError):patch_index(index)

    def test_actual_page_draw_is_bounded_to_its_viewport(self):
        # Execute the production method, not a second implementation of its
        # clipping policy. The controlled Canvas uses JDK raster/clip semantics;
        # it is not an Android/GPU/e-ink pass. RN's parent may allow overflow.
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    @Override protected void onDraw(Canvas canvas){')
        end=source.index('    private int charAt(',begin)
        method=source[begin:end].replace('@Override ','')
        harness=r'''import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.ArrayDeque;
import java.util.Deque;

class Color {static final int WHITE=0xffffffff,BLACK=0xff000000;}
class Paint {int color;void setColor(int value){color=value;}}
class Bitmap {
 final BufferedImage image;
 Bitmap(int w,int h,int color){image=new BufferedImage(w,h,BufferedImage.TYPE_INT_ARGB);
  Graphics2D g=image.createGraphics();g.setColor(new java.awt.Color(color,true));g.fillRect(0,0,w,h);g.dispose();}
 int getWidth(){return image.getWidth();}int getHeight(){return image.getHeight();}
}
class Canvas {
 final BufferedImage image=new BufferedImage(280,220,BufferedImage.TYPE_INT_ARGB);
 Graphics2D g=image.createGraphics();final Deque<Graphics2D> saved=new ArrayDeque<>();
 Canvas(){g.setClip(0,0,280,220);drawColor(0xff00ff00);}
 int save(){saved.push(g);g=(Graphics2D)g.create();return saved.size();}
 void restoreToCount(int count){while(saved.size()>=count){g.dispose();g=saved.pop();}}
 void clipRect(float l,float t,float r,float b){g.clip(new java.awt.geom.Rectangle2D.Float(l,t,r-l,b-t));}
 void drawColor(int color){Paint p=new Paint();p.setColor(color);drawRect(-10000,-10000,10000,10000,p);}
 void drawBitmap(Bitmap b,float x,float y,Paint p){g.drawImage(b.image,Math.round(x),Math.round(y),null);}
 void drawRect(float l,float t,float r,float b,Paint p){g.setColor(new java.awt.Color(p.color,true));g.fill(new java.awt.geom.Rectangle2D.Float(l,t,r-l,b-t));}
 void translate(int x,int y){g.translate(x,y);}int pixel(int x,int y){return image.getRGB(x,y);}
}
class JSONObject {
 boolean broken;JSONObject(boolean fail){broken=fail;}
 JSONArray getJSONArray(String name)throws Exception{if(broken)throw new Exception("selection fixture");return new JSONArray();}
}
class JSONArray {
 JSONObject getJSONObject(int index){return new JSONObject(false);}
 double getDouble(int index){return index<2?-50:250;}
}
class ActualPage {
 Bitmap bitmap;JSONObject model;int start=-1,end=-1;long revision;int failures;
 float x=10,y=10;final Paint paint=new Paint();
 int getWidth(){return 100;}int getHeight(){return 140;}
 void fail(long ticket,String message){failures++;}
 /*ACTUAL_ON_DRAW*/
}
public class DrawTest {
 static int assertions;static final int GREEN=0xff00ff00,BLUE=0xff0000ff,RED=0xffff0000;
 static void ok(boolean value,String label){if(!value)throw new AssertionError(label);assertions++;}
 static ActualPage page(int color){ActualPage p=new ActualPage();p.bitmap=new Bitmap(70,100,color);return p;}
 static void draw(Canvas c,ActualPage p,int x,int y){int parent=c.save();c.translate(x,y);
  int depth=c.saved.size();java.awt.Shape clip=c.g.getClip();p.onDraw(c);
  ok(c.saved.size()==depth,"page restores save depth");
  ok(c.g.getClip().getBounds().equals(clip.getBounds()),"page restores parent clip");c.restoreToCount(parent);}
 static void untouched(Canvas c){ok(c.pixel(5,5)==GREEN,"header survives");ok(c.pixel(5,210)==GREEN,"footer survives");
  ok(c.pixel(5,90)==GREEN,"outer margin survives");ok(c.pixel(121,90)==GREEN,"gutter survives");}
 public static void main(String[] args){
  for(boolean reverse:new boolean[]{false,true}){
   Canvas c=new Canvas();ActualPage left=page(BLUE),right=page(RED);
   if(reverse){draw(c,right,123,30);draw(c,left,20,30);}else{draw(c,left,20,30);draw(c,right,123,30);}
   ok(c.pixel(45,65)==BLUE,"left original page survives sibling");ok(c.pixel(148,65)==RED,"right original page survives sibling");
   ok(c.pixel(22,32)==Color.WHITE,"white viewport background drawn");untouched(c);
  }
  Canvas empty=new Canvas();draw(empty,new ActualPage(),20,30);
  ok(empty.pixel(22,32)==Color.WHITE,"empty viewport fills only itself");untouched(empty);
  ActualPage panned=page(BLUE);panned.bitmap=new Bitmap(220,220,BLUE);panned.x=-40;panned.y=-35;
  Canvas pan=new Canvas();draw(pan,panned,20,30);ok(pan.pixel(22,32)==BLUE,"negative pan retained");
  ok(pan.pixel(119,169)==BLUE,"bitmap reaches viewport edge");untouched(pan);
  ActualPage selected=page(RED);selected.bitmap=new Bitmap(220,220,RED);selected.x=-40;selected.y=-35;
  selected.model=new JSONObject(false);selected.start=selected.end=0;
  Canvas selection=new Canvas();draw(selection,selected,20,30);
  ok(selection.pixel(45,65)!=RED,"selection actually painted");untouched(selection);
  ActualPage small=page(RED);small.model=new JSONObject(false);small.start=small.end=0;
  Canvas smallSelection=new Canvas();draw(smallSelection,small,20,30);
  ok(smallSelection.pixel(22,32)==Color.WHITE,"selection is also bounded by bitmap");
  ok(smallSelection.pixel(45,65)!=RED,"small selection actually painted");untouched(smallSelection);
  selected.model=new JSONObject(true);Canvas failure=new Canvas();draw(failure,selected,20,30);
  ok(selected.failures==1,"selection failure exercised");untouched(failure);
  System.out.println(assertions+" actual onDraw controlled-raster assertions PASS (not Android hardware)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-page-paint-') as temp:
            root=Path(temp);java=root/'DrawTest.java'
            def run(body):
                java.write_text(harness.replace('/*ACTUAL_ON_DRAW*/',body),encoding='utf-8')
                subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(java)],check=True)
                return subprocess.run([str(home/('java'+suffix)),'-Djava.awt.headless=true','-cp',temp,'DrawTest'],
                    capture_output=True,text=True)
            correct=run(method)
            self.assertEqual(correct.returncode,0,correct.stderr)
            print(correct.stdout.strip())
            mutations=(
                ('missing owner clip','canvas.clipRect(0,0,getWidth(),getHeight());','',
                 'left original page survives sibling'),
                ('missing owner restore','canvas.restoreToCount(viewport);','',
                 'page restores save depth'),
                ('missing bitmap selection clip','canvas.clipRect(x,y,x+bitmap.getWidth(),y+bitmap.getHeight());','',
                 'selection is also bounded by bitmap'),
            )
            for label,old,new,failure in mutations:
                self.assertEqual(method.count(old),1,label)
                broken=run(method.replace(old,new,1))
                self.assertNotEqual(broken.returncode,0,label)
                self.assertIn(failure,broken.stderr,label)
            print('3 compiled actual-onDraw defect mutants rejected')

    def test_rejection_snapshot_preserves_actual_admission(self):
        # Actual ledger/report method, controlled Log peer. Numeric admission
        # evidence only: this does not prove Android heap size or owner lifetime.
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    private void reportRasterRejection(')
        report=source[begin:source.index('    private void fail(',begin)]
        begin=source.index('    private void fail(')
        failure=source[begin:source.index('    private void releaseFrame()',begin)]
        harness=r'''package test;
class WritableMap {void putString(String key,String value){}}
class ActualPage {
 boolean disposed,failed,ready=true,pressed=true;long revision=8;int getId(){return 77;}
 int start=1,end=2,events;String selected="old";
 WritableMap packet(String kind){return new WritableMap();}
 void emit(WritableMap event){events++;}void invalidate(){}
 /*ACTUAL_REPORT*/
 /*ACTUAL_FAIL*/
 void report(long ticket,Throwable error){reportRasterRejection(ticket,5,error);}
 void publish(long ticket,long renderToken,Throwable error){reportRasterRejection(ticket,renderToken,error);fail(ticket,"PDF page/zoom rejected: "+error.getMessage());}
}
public class SnapshotTest {
 static int assertions;static void ok(boolean b,String label){if(!b)throw new AssertionError(label);assertions++;}
 static PdfiumRasterLedger.Rejected reject(PdfiumRasterLedger ledger,long pixels,long source){
  try{ledger.reserve(pixels,source);throw new AssertionError("unexpected admission");}
  catch(PdfiumRasterLedger.Rejected error){return error;}
 }
 public static void main(String[] args)throws Exception {
  PdfiumRasterLedger ledger=new PdfiumRasterLedger(100000000);
  PdfiumRasterLedger.Lease prior=ledger.reserve(3000000,0);prior.installed();
  PdfiumRasterLedger.Rejected error=reject(ledger,3000000,20000000);
  ok(error.pixels==3000000&&error.chargeBytes==26097152,"attempt snapshot");
  ok(error.sourceBytes==20000000&&error.usedBytes==12000000&&error.limitBytes==50000000,"atomic existing operands");
  ok(error.getMessage().equals("Zoom exceeds the shared raster budget; use Fit"),"user message unchanged");
  ok(ledger.used()==12000000,"rejection does not charge or retire another owner");
  for(java.lang.reflect.Field field:PdfiumRasterLedger.Rejected.class.getDeclaredFields())
   ok(java.lang.reflect.Modifier.isFinal(field.getModifiers()),"snapshot immutable");
  prior.release();prior.release();ok(ledger.used()==0&&error.usedBytes==12000000,"snapshot survives later ledger changes");
  PdfiumRasterLedger.Lease next=ledger.reserve(3000000,20000000);
  ok(ledger.used()==26097152,"same predicate admits after legitimate charge is released");
  next.installed();next.installed();ok(ledger.used()==12000000,"successful installation unchanged");
  next.release();ok(ledger.used()==0,"successful release unchanged");
  PdfiumRasterLedger.Rejected intrinsic=reject(ledger,1,49000000);
  ok(intrinsic.usedBytes==0&&intrinsic.sourceBytes+intrinsic.chargeBytes>intrinsic.limitBytes,"intrinsic pressure distinguishable");
  boolean invalid=false;try{ledger.reserve(6000001,0);}catch(IllegalArgumentException expected){invalid=true;}
  ok(invalid&&ledger.used()==0,"raster cap not bypassed");
  ActualPage page=new ActualPage();page.report(7,error);
  ok(android.util.Log.calls==0,"stale rejection not published");
  page.disposed=true;page.report(8,error);page.disposed=false;
  page.failed=true;page.report(8,error);page.failed=false;
  page.report(8,new IllegalStateException("other failure"));
  ok(android.util.Log.calls==0,"disposed/failed/unrelated rejection not published");
  page.report(8,error);
  ok(android.util.Log.calls==1&&android.util.Log.tag.equals("RTL_PDFIUM_RASTER"),"one admitted numeric diagnostic");
  ok(android.util.Log.text.equals("rejected view=77 ticket=8 renderToken=5 pixels=3000000 chargeBytes=26097152 sourceBytes=20000000 usedBytes=12000000 limitBytes=50000000"),"numeric original-scene snapshot has no path/content/hash");
  ok(!page.disposed&&!page.failed&&page.revision==8&&ledger.used()==0,"diagnostic does not change state/admission");
  android.util.Log.reject=1;page.report(8,error);
  ok(!page.failed&&page.revision==8&&ledger.used()==0,"logging failure cannot alter existing failure path");
  for(int rejection:new int[]{0,1,2}){
   android.util.Log.reject=rejection;ActualPage terminal=new ActualPage();
   terminal.publish(8,41,error);
   ok(terminal.failed&&!terminal.ready&&!terminal.pressed&&terminal.events==1,"actual fail continues after log success/runtime/linkage failure");
   ok(ledger.used()==0&&error.usedBytes==12000000,"terminal publication preserves snapshot/accounting");
  }
  android.util.Log.reject=0;ActualPage stale=new ActualPage();stale.publish(7,40,error);
  ok(!stale.failed&&stale.events==0,"stale admitted callback cannot latch a newer view revision");
  System.out.println(assertions+" actual rejection snapshot/report assertions PASS (controlled Log)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-rejection-') as temp:
            root=Path(temp);java=root/'SnapshotTest.java';ledger=root/'PdfiumRasterLedger.java'
            log=root/'android/util/Log.java';log.parent.mkdir(parents=True)
            log.write_text('package android.util; public class Log { public static int calls,reject; public static String tag,text; public static int w(String t,String s){if(reject==1)throw new SecurityException("controlled log failure");if(reject==2)throw new LinkageError("controlled log linkage failure");calls++;tag=t;text=s;return 0;} }',encoding='utf-8')
            ledger.write_text((ROOT/'native/PdfiumRasterLedger.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            def run(body):
                java.write_text(harness.replace('/*ACTUAL_REPORT*/',body).replace('/*ACTUAL_FAIL*/',failure),encoding='utf-8')
                subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(log),str(ledger),str(java)],check=True)
                return subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.SnapshotTest'],capture_output=True,text=True)
            correct=run(report);self.assertEqual(correct.returncode,0,correct.stderr);print(correct.stdout.strip())
            broken=run(report.replace('revision!=ticket || ',''))
            self.assertNotEqual(broken.returncode,0);self.assertIn('stale rejection not published',broken.stderr)
            self.assertIn('reportRasterRejection(ticket,command.optLong("renderToken",-1),error);fail(ticket,',source)

    def test_aggregate_ledger_actual_java(self):
        home=Path(os.environ['JAVA_HOME'])/'bin'
        suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-ledger-') as temp:
            root=Path(temp)
            (root/'PdfiumRasterLedger.java').write_text((ROOT/'native/PdfiumRasterLedger.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (root/'PdfiumViewport.java').write_text((ROOT/'native/PdfiumViewport.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (root/'LedgerTest.java').write_text('''package test;
public class LedgerTest {
static void ok(boolean b){if(!b)throw new AssertionError();}
public static void main(String[] args){
PdfiumRasterLedger ledger=new PdfiumRasterLedger(100000000);
PdfiumRasterLedger.Lease a=ledger.reserve(3000000,0);a.installed();
ok(ledger.used()==12000000);PdfiumRasterLedger.Lease b=ledger.reserve(3000000,0);ok(ledger.used()==38097152);
boolean refused=false;try{ledger.reserve(3000000,0);}catch(IllegalStateException e){refused=true;}ok(refused);
b.release();b.release();ok(ledger.used()==12000000);
a.installed();ok(ledger.used()==12000000);a.release();ok(ledger.used()==0);
refused=false;try{ledger.reserve(6000001,0);}catch(IllegalArgumentException e){refused=true;}ok(refused);
refused=false;try{ledger.reserve(5000000,20000000);}catch(IllegalStateException e){refused=true;}ok(refused);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill",null,"left")==1);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill","Fit","left")==.96);
ok(PdfiumViewport.baseScale(600,800,600,800,"fit","Fit","right")==.96);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill","Fit","right")==.72);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill",null,"right")==1.5);
refused=false;try{PdfiumViewport.baseScale(20,600,600,800,"fit","Fit","single");}catch(IllegalArgumentException e){refused=true;}ok(refused);
ok(PdfiumViewport.baseScale(600,800,600,800,"fit",null,"single")==1);
ok(PdfiumViewport.baseScale(600,700,600,800,"fit",null,"single")==.875);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill","Fit","single")==1);
ok(PdfiumViewport.pinchScale(600,800,600,800,"single",1,1.25)==1.25);
ok(PdfiumViewport.pinchScale(600,800,600,800,"single",1,.5)==1);
ok(PdfiumViewport.pinchScale(600,800,600,800,"single",3,2)==4);
for(double bad:new double[]{Double.NaN,Double.POSITIVE_INFINITY,0,-1,.49,2.01}){
 refused=false;try{PdfiumViewport.pinchScale(600,800,600,800,"single",1,bad);}catch(IllegalArgumentException e){refused=true;}ok(refused);
}
System.out.println("26 actual shared-raster/Fit/pinch assertions PASS");}}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,
                str(root/'PdfiumRasterLedger.java'),str(root/'PdfiumViewport.java'),str(root/'LedgerTest.java')],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.LedgerTest'],check=True)

    def test_detached_page_retires_only_its_actual_frame_budget(self):
        # Real methods and ledger, controlled View/Bitmap peers. This establishes
        # the detach-before-RN-drop lifetime, not its frequency or a device heap.
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    private boolean current(')
        current=source[begin:source.index('    private void schedule()',begin)]
        begin=source.index('    private void schedule(){')+len('    private void schedule(){')
        admission=source[begin:source.index('        final JSONObject command=',begin)]
        begin=source.index('    private void releaseFrame()')
        lifecycle=source[begin:source.index('    @Override protected void onDraw',begin)]
        harness=r'''package test;
class Parent {
 int detaches,attaches;
 protected void onSizeChanged(int w,int h,int oldW,int oldH){}
 protected void onDetachedFromWindow(){detaches++;}
 protected void onAttachedToWindow(){attaches++;}
}
class Frame {int recycles;void recycle(){recycles++;}}
class Request {
 String optString(String name){return name.equals("sessionId")?"11":"stamp";}
 boolean optBoolean(String name,boolean fallback){return false;}
}
class ActualPage extends Parent {
 long revision=8;boolean disposed,attached=true,failed,ready=true,pressed=true;Frame bitmap=new Frame();
 Object model=new Object();Request request=new Request();PdfiumRasterLedger.Lease lease;
 int schedules;int getWidth(){return 100;}int getHeight(){return 140;}
 void schedule(){/*ACTUAL_SCHEDULE_ADMISSION*/ schedules++;}
 boolean accepts(long ticket){return current(ticket,"11","stamp");}
 /*ACTUAL_CURRENT*/
 /*ACTUAL_LIFECYCLE*/
}
public class DetachTest {
 static int assertions;static void ok(boolean b,String label){if(!b)throw new AssertionError(label);assertions++;}
 public static void main(String[] args){
  PdfiumRasterLedger ledger=new PdfiumRasterLedger(100000000);
  PdfiumRasterLedger.Lease sibling=ledger.reserve(500000,0);sibling.installed();
  ActualPage p=new ActualPage();p.lease=ledger.reserve(3000000,0);p.lease.installed();
  Frame old=p.bitmap;ok(ledger.used()==14000000,"two actual frame owners charged");
  ok(p.accepts(8),"old ticket initially current");
  boolean refused=false;try{ledger.reserve(3000000,20000000);}catch(IllegalStateException e){refused=true;}
  ok(refused,"retired frame can block a bounded replacement");
  p.onDetachedFromWindow();
  ok(!p.ready&&!p.pressed,"detach fences readiness and touch");
  ok(!p.accepts(8),"detach rejects in-flight old completion");
  ok(p.detaches==1,"parent detach still called");
  ok(p.bitmap==null&&p.model==null&&p.lease==null,"detached frame/model/lease retired before RN drop");
  ok(old.recycles==1,"owned bitmap recycled once");
  ok(ledger.used()==2000000,"detach preserves sibling's live charge");
  // A late RN property transaction must not rearm an off-window old view.
  p.revision++;ok(!p.accepts(p.revision),"detached view rejects even a newly committed ticket");
  p.schedule();ok(p.schedules==0,"off-window commit cannot allocate a replacement frame");
  PdfiumRasterLedger.Lease replacement=ledger.reserve(3000000,20000000);
  ok(ledger.used()==28097152,"same replacement fits without changing cap/source accounting");
  replacement.release();p.onAttachedToWindow();
  ok(p.attaches==1&&p.schedules==1,"reattach schedules a fresh frame");
  ok(!p.ready&&p.bitmap==null,"reattach cannot resurrect retired pixels");
  p.onDetachedFromWindow();p.dispose();p.dispose();
  ok(ledger.used()==2000000&&old.recycles==1,"repeat detach/drop cannot double-free sibling or bitmap");
  p.onAttachedToWindow();ok(p.schedules==1,"disposed view cannot rearm");
  sibling.release();ok(ledger.used()==0,"all actual owners balanced");
  System.out.println(assertions+" actual detach/current/frame/ledger assertions PASS (controlled peers)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-page-detach-') as temp:
            root=Path(temp);java=root/'DetachTest.java'
            ledger=root/'PdfiumRasterLedger.java'
            ledger.write_text((ROOT/'native/PdfiumRasterLedger.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            def run(body,guard=current,schedule=admission):
                java.write_text(harness.replace('/*ACTUAL_CURRENT*/',guard).replace('/*ACTUAL_SCHEDULE_ADMISSION*/',schedule).replace('/*ACTUAL_LIFECYCLE*/',body),encoding='utf-8')
                subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(ledger),str(java)],check=True)
                return subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.DetachTest'],capture_output=True,text=True)
            correct=run(lifecycle)
            self.assertEqual(correct.returncode,0,correct.stderr)
            print(correct.stdout.strip())
            old='pressed=false;releaseFrame();super.onDetachedFromWindow();'
            self.assertEqual(lifecycle.count(old),1)
            broken=run(lifecycle.replace(old,'pressed=false;super.onDetachedFromWindow();',1))
            self.assertNotEqual(broken.returncode,0)
            self.assertIn('detached frame/model/lease retired before RN drop',broken.stderr)
            for label,guard,schedule,failure in (
                ('off-window completion',current.replace('attached && ',''),admission,'detached view rejects even a newly committed ticket'),
                ('off-window scheduling',current,admission.replace('!attached || ',''),'off-window commit cannot allocate a replacement frame'),
            ):
                broken=run(lifecycle,guard,schedule)
                self.assertNotEqual(broken.returncode,0,label)
                self.assertIn(failure,broken.stderr,label)
            print('3 compiled detach/frame/late-commit defect mutants rejected')

    def test_native_failure_fences_geometry_before_react_error_props(self):
        # Execute the production terminal-failure/admission methods. Layout and
        # React publication ordering are controlled peers, not Android timing.
        source=(ROOT/'native/PdfiumPageView.java.template').read_text(encoding='utf-8')
        begin=source.index('    private boolean current(')
        current=source[begin:source.index('    private void schedule()',begin)]
        begin=source.index('    private void schedule(){')+len('    private void schedule(){')
        admission=source[begin:source.index('        final JSONObject command=',begin)]
        begin=source.index('    private void fail(long ticket,String message){')
        failure=source[begin:source.index('    private void releaseFrame()',begin)]
        begin=source.index('    private volatile boolean ')
        flags=source[begin:source.index(';',begin)+1]
        harness=r'''package test;
class Request {
 String optString(String name){return name.equals("sessionId")?"11":"stamp";}
 boolean optBoolean(String name,boolean fallback){return false;}
}
class WritableMap {void putString(String key,String value){}}
class ActualPage {
 /*ACTUAL_FLAGS*/
 long revision=8;boolean ready=true,pressed=true;int start=1,end=2;String selected="old";
 Request request=new Request();int schedules,events,invalidations;
 ActualPage(){attached=true;}
 int getWidth(){return 600;}int getHeight(){return 900;}
 void schedule(){/*ACTUAL_SCHEDULE_ADMISSION*/schedules++;}
 WritableMap packet(String kind){return new WritableMap();}
 void emit(WritableMap event){events++;}void invalidate(){invalidations++;}
 void error(long ticket){fail(ticket,"budget");}
 boolean accepts(){return current(revision,"11","stamp");}
 void lateGeometry(){++revision;schedule();}
 void replaceSameViewRequest(){request=new Request();++revision;schedule();}
 void markDisposed(){disposed=true;}
 boolean latched(){return failed;}
 /*ACTUAL_CURRENT*/
 /*ACTUAL_FAIL*/
}
public class FailureTest {
 static int assertions;static void ok(boolean b,String label){if(!b)throw new AssertionError(label);assertions++;}
 public static void main(String[] args){
  ActualPage p=new ActualPage();p.error(7);
  ok(!p.latched()&&p.ready&&p.events==0,"stale failure cannot poison current view");
  p.error(8);ok(p.latched(),"current native failure latches before React props");
  ok(!p.ready&&!p.pressed&&p.start==-1&&p.end==-1&&p.selected.isEmpty(),"failure fences interaction");
  ok(p.events==1&&p.invalidations==1,"one current failure emitted");
  ok(!p.accepts(),"failed view rejects current-stamp completion");
  p.schedule();ok(p.schedules==0,"failed view refuses direct reschedule");
  p.lateGeometry();ok(p.schedules==0&&!p.accepts(),"queued geometry cannot retry failed pose");
  p.replaceSameViewRequest();ok(p.schedules==0&&!p.accepts(),"same-view property commit cannot clear latch");
  p.error(p.revision);ok(p.events==1,"duplicate failures do not loop error layout");
  ActualPage fresh=new ActualPage();fresh.error(7);
  fresh.schedule();ok(!fresh.latched()&&fresh.accepts()&&fresh.schedules==1,"explicit fresh keyed view can render Fit");
  p.markDisposed();p.error(p.revision);ok(p.events==1,"disposed old view cannot publish into new mount");
  System.out.println(assertions+" actual failure/current/schedule assertions PASS (controlled peers)");
 }
}
'''
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-page-failure-') as temp:
            java=Path(temp)/'FailureTest.java'
            def run(guard=current,schedule=admission,fail=failure):
                java.write_text(harness.replace('/*ACTUAL_FLAGS*/',flags).replace('/*ACTUAL_CURRENT*/',guard)
                    .replace('/*ACTUAL_SCHEDULE_ADMISSION*/',schedule).replace('/*ACTUAL_FAIL*/',fail),encoding='utf-8')
                subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(java)],check=True)
                return subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.FailureTest'],capture_output=True,text=True)
            correct=run();self.assertEqual(correct.returncode,0,correct.stderr);print(correct.stdout.strip())
            for label,guard,schedule,fail,expected in (
                ('missing latch',current,admission,failure.replace('failed=true;',''),'current native failure latches'),
                ('retry after failure',current,admission.replace('failed || ',''),failure,'failed view refuses direct reschedule'),
                ('stale completion after failure',current.replace('!failed && ',''),admission,failure,'failed view rejects current-stamp completion'),
                ('stale failure poisons current view',current,admission,failure.replace('revision!=ticket || ',''),'stale failure cannot poison current view'),
            ):
                broken=run(guard,schedule,fail);self.assertNotEqual(broken.returncode,0,label);self.assertIn(expected,broken.stderr,label)
            print('4 compiled native-failure/geometry/stale-ticket defect mutants rejected')


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--emit':
        output=Path(sys.argv[2]);output.mkdir(parents=True,exist_ok=False);generated(output)
        java=output/'android/app/src/main/java/com/supernotertlreader';java.mkdir(parents=True)
        (java/'PdfRendererPackage.kt').write_text((ROOT/'native/PdfRendererPackage.kt.template').read_text().replace(
            '__PACKAGE__','com.supernotertlreader'),encoding='utf-8')
    else:unittest.main()
