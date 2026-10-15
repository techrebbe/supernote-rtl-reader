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
    def test_real_generated_slots_and_guards(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-integrated-app-') as temp:
            app,index=generated(Path(temp))
            self.assertEqual(app.count('<InteractivePdfPage'),3)
            self.assertNotIn('<NativePdfPageView',app)
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

class Color {static final int LTGRAY=0xffcccccc,BLACK=0xff000000;}
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
   ok(c.pixel(22,32)==Color.LTGRAY,"viewport background drawn");untouched(c);
  }
  Canvas empty=new Canvas();draw(empty,new ActualPage(),20,30);
  ok(empty.pixel(22,32)==Color.LTGRAY,"empty viewport fills only itself");untouched(empty);
  ActualPage panned=page(BLUE);panned.bitmap=new Bitmap(220,220,BLUE);panned.x=-40;panned.y=-35;
  Canvas pan=new Canvas();draw(pan,panned,20,30);ok(pan.pixel(22,32)==BLUE,"negative pan retained");
  ok(pan.pixel(119,169)==BLUE,"bitmap reaches viewport edge");untouched(pan);
  ActualPage selected=page(RED);selected.bitmap=new Bitmap(220,220,RED);selected.x=-40;selected.y=-35;
  selected.model=new JSONObject(false);selected.start=selected.end=0;
  Canvas selection=new Canvas();draw(selection,selected,20,30);
  ok(selection.pixel(45,65)!=RED,"selection actually painted");untouched(selection);
  ActualPage small=page(RED);small.model=new JSONObject(false);small.start=small.end=0;
  Canvas smallSelection=new Canvas();draw(smallSelection,small,20,30);
  ok(smallSelection.pixel(22,32)==Color.LTGRAY,"selection is also bounded by bitmap");
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
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill",null)==1);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill","Fit")==.96);
ok(PdfiumViewport.baseScale(600,800,600,800,"fit","Fit")==.96);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill","Fit")==.72);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill",null)==1.5);
refused=false;try{PdfiumViewport.baseScale(20,600,600,800,"fit","Fit");}catch(IllegalArgumentException e){refused=true;}ok(refused);
System.out.println("14 actual shared-raster/Fit assertions PASS");}}
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
 long revision=8;boolean disposed,attached=true,ready=true,pressed=true;Frame bitmap=new Frame();
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


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--emit':
        output=Path(sys.argv[2]);output.mkdir(parents=True,exist_ok=False);generated(output)
        java=output/'android/app/src/main/java/com/supernotertlreader';java.mkdir(parents=True)
        (java/'PdfRendererPackage.kt').write_text((ROOT/'native/PdfRendererPackage.kt.template').read_text().replace(
            '__PACKAGE__','com.supernotertlreader'),encoding='utf-8')
    else:unittest.main()
