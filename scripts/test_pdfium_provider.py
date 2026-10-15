"""Private-provider ELF controls and actual Java input authentication, offline only."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import shutil
import tempfile
import unittest
import zipfile
from pdfium_provider import generate

ROOT=Path(__file__).resolve().parents[1]
CALLS='FPDF_InitLibrary(); FPDF_CloseDocument(nullptr);'


def fixture(kind=1026, target=2048, addend=0):
    strings=b'\0FPDF_InitLibrary\0FPDF_CloseDocument\0'
    symbols=bytes(24)+struct.pack('<IBBHQQ',1,0x12,0,1,1024,16)+struct.pack('<IBBHQQ',18,0x12,0,1,1040,16)
    data_start=64+56+4*64
    sym_start=data_start+len(strings)
    rel_start=sym_start+len(symbols)
    header=bytearray(64);header[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH',header,16,3,183)
    struct.pack_into('<QQ',header,32,64,120)
    struct.pack_into('<HHHH',header,54,56,1,64,4)
    program=struct.pack('<IIQQQQQQ',1,5,0,0,0,rel_start+24,4096,4096)
    sections=bytes(64)
    for kind_value,offset,size,link,stride in ((3,data_start,len(strings),0,0),(11,sym_start,len(symbols),1,24),(4,rel_start,24,2,24)):
        sections+=struct.pack('<IIQQQQIIQQ',0,kind_value,0,0,offset,size,link,0,1,stride)
    return bytes(header)+program+sections+strings+symbols+struct.pack('<QQq',target,(2<<32)|kind,addend)


def header(data,core=CALLS):
    return generate(core,data,hashlib.sha256(data).hexdigest())


class Provider(unittest.TestCase):
    def test_actual_native_release_and_rejected_reference_are_terminal(self):
        compiler=os.environ.get('CXX') or shutil.which('g++')
        if not compiler:self.skipTest('A host C++17 compiler is needed for controlled native teardown callbacks')
        source=(ROOT/'native/pdfium_provider.h').read_text()
        def function(marker):
            start=source.index(marker);brace=source.index('{',start);depth=1;end=brace+1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[start:end]
        declarations=source[source.index('static Api currentApi;'):source.index('const Api& api()')]
        body='''#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>
#include <iostream>
struct Api {int sentinel=0;};
static int closes=0,closeResult=0;
static int dlclose(void*){closes++;return closeResult;}
namespace rtl_provider {
'''+declarations+function('static void discardRejectedReference(')+function('static void release()')+'''
}
static int assertions;
static void ok(bool b){if(!b)throw std::runtime_error("failed assertion");assertions++;}
static void reset(){using namespace rtl_provider;currentApi=Api{};ready=false;engineHandle=nullptr;engineBase=nullptr;engineName.clear();poisoned=false;closes=closeResult=0;}
int main(){using namespace rtl_provider;
 reset();release();release();ok(closes==0);ok(!ready);ok(!poisoned);
 reset();engineHandle=reinterpret_cast<void*>(1);engineBase=engineHandle;engineName="installed";currentApi.sentinel=7;ready=true;
 release();ok(closes==1);ok(!ready);ok(engineHandle==nullptr);ok(engineBase==nullptr);ok(engineName.empty());ok(currentApi.sentinel==0);
 release();ok(closes==1);
 reset();engineHandle=reinterpret_cast<void*>(2);ready=true;currentApi.sentinel=7;closeResult=-1;
 try{release();throw 1;}catch(const std::runtime_error&){assertions++;}
 ok(poisoned);ok(!ready);ok(currentApi.sentinel==0);ok(engineHandle==reinterpret_cast<void*>(2));ok(closes==1);
 try{release();throw 1;}catch(const std::runtime_error&){assertions++;}ok(closes==1);
 reset();discardRejectedReference(reinterpret_cast<void*>(3));ok(closes==1);ok(!poisoned);ok(engineHandle==nullptr);
 reset();closeResult=-1;discardRejectedReference(reinterpret_cast<void*>(4));ok(closes==1);ok(poisoned);ok(engineHandle==reinterpret_cast<void*>(4));
 try{release();throw 1;}catch(const std::runtime_error&){assertions++;}ok(closes==1);
 std::cout<<assertions<<" actual native teardown-function assertions PASS; dlclose callback is controlled, not Android loading"<<std::endl;
}
'''
        with tempfile.TemporaryDirectory(prefix='rtl-native-release-') as temp:
            folder=Path(temp);file=folder/'release.cpp';file.write_text(body,encoding='utf-8')
            output=folder/('release.exe' if os.name=='nt' else 'release')
            subprocess.run([compiler,'-std=c++17','-pthread',str(file),'-o',str(output)],check=True)
            subprocess.run([str(output)],check=True)

    def test_typed_calls_and_internal_witness(self):
        result=header(fixture())
        self.assertIn('decltype(&::FPDF_InitLibrary)',result)
        self.assertIn('decltype(&::FPDF_CloseDocument)',result)
        self.assertIn('{2048ULL,"FPDF_CloseDocument"}',result)
        self.assertIn('#define FPDF_InitLibrary (rtl_provider::api().fn_FPDF_InitLibrary)',result)

    def test_input_digest_is_not_replaced_by_metadata(self):
        with self.assertRaisesRegex(ValueError,'authenticated engine'):
            generate(CALLS,fixture(),'0'*64)

    def test_calls_must_exist_and_comments_do_not_add_them(self):
        header(fixture(),CALLS+' // FPDF_Unimplemented();\n/* FPDF_Absent(); */')
        for core in ('// FPDF_InitLibrary();',CALLS+' FPDF_Absent();'):
            with self.assertRaisesRegex(ValueError,'call/export inventory'):header(fixture(),core)

    def test_unknown_or_adjusted_api_relocation_rejected(self):
        for data in (fixture(kind=0),fixture(addend=1)):
            with self.assertRaisesRegex(ValueError,'Unsupported internal'):header(data)

    def test_relocation_slot_must_be_readable(self):
        for target in (4090,2**63):
            with self.assertRaisesRegex(ValueError,'outside readable'):header(fixture(target=target))

    def test_machine_section_and_symbol_bounds(self):
        original=fixture()
        mutations=[]
        machine=bytearray(original);struct.pack_into('<H',machine,18,62);mutations.append(machine)
        sections=bytearray(original);struct.pack_into('<Q',sections,40,2**63);mutations.append(sections)
        symbols=bytearray(original);struct.pack_into('<I',symbols,len(original)-16,0xffffffff);mutations.append(symbols)
        mutations.append(original[:-1])
        for value in mutations:
            with self.assertRaises(ValueError):header(value)

    def test_actual_pinned_engine_witness(self):
        path=os.environ.get('RTL_PDFIUM_PROVIDER_ENGINE')
        apk=os.environ.get('RTL_PDFIUM_PROVIDER_APK')
        if path:data=Path(path).read_bytes()
        elif apk:
            with zipfile.ZipFile(apk) as archive:data=archive.read('lib/arm64-v8a/libpdfium.so')
        else:self.skipTest('Set actual authenticated engine path or APK')
        result=generate((ROOT/'probes/pdfium-native/native_core.cpp').read_text(),data,
            'e6b7257b3905152dab64c79f7a4a570693e11ccb740e92e4d3b89c28df6fcbbb')
        self.assertEqual(result.count('decltype('),39)
        self.assertEqual(result.count('ULL,"FPDF'),7)

    def test_actual_java_authentication_and_shared_classes_compile(self):
        apk=os.environ.get('RTL_PDFIUM_PROVIDER_APK')
        sdk=os.environ.get('ANDROID_HOME')
        if not apk or not sdk or not os.environ.get('JAVA_HOME'):
            self.skipTest('Set actual APK, Android SDK and JDK17')
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        android=Path(sdk)/'platforms/android-35/android.jar'
        with tempfile.TemporaryDirectory(prefix='rtl-provider-java-') as temp:
            folder=Path(temp);sources=[]
            for name in ('PdfiumReaderCore','PdfiumEngine','PdfiumSession','PdfiumRasterLedger','PdfiumViewport'):
                path=folder/(name+'.java');path.write_text((ROOT/'native'/(name+'.java.template')).read_text().replace('__PACKAGE__','test'),encoding='utf-8');sources.append(str(path))
            probe=folder/'ProviderTest.java'
            probe.write_text('''package test;
import java.io.*;import java.lang.reflect.*;import java.util.zip.*;
public final class ProviderTest {
static int count;
static void ok(boolean value){if(!value)throw new AssertionError();count++;}
static Object call(String name,Class<?> type,Object arg)throws Exception{
 Method method=PdfiumEngine.class.getDeclaredMethod(name,type);method.setAccessible(true);
 try{return method.invoke(null,arg);}catch(InvocationTargetException e){throw (Exception)e.getCause();}
}
static void rejected(String origin)throws Exception{
 try{call("physicalPath",String.class,origin);throw new AssertionError("accepted unsupported input");}
 catch(IllegalStateException expected){count++;}
}
static void authenticate(byte[] bytes)throws Exception{
 Method method=PdfiumEngine.class.getDeclaredMethod("authenticate",byte[].class,String.class);method.setAccessible(true);
 try{method.invoke(null,bytes,"/installed/libpdfium.so");}catch(InvocationTargetException e){throw (Exception)e.getCause();}
}
public static void main(String[] args)throws Exception{
 String apk=new File(args[0]).toURI().getPath();
 byte[] engine;
 try(ZipFile zip=new ZipFile(args[0]);InputStream input=zip.getInputStream(zip.getEntry("lib/arm64-v8a/libpdfium.so"))){
  engine=(byte[])call("bytes",InputStream.class,input);
 }
 ok(engine.length==6573320);
 ok(call("digest",byte[].class,engine).equals("e6b7257b3905152dab64c79f7a4a570693e11ccb740e92e4d3b89c28df6fcbbb"));
 authenticate(engine);count++;
 ok(call("physicalPath",String.class,"/installed/libpdfium.so").equals("/installed/libpdfium.so"));
 rejected(apk+"!/lib/arm64-v8a/libpdfium.so");rejected(apk+"!/lib/armeabi-v7a/libpdfium.so");
 rejected(apk+"!/other.so");rejected("relative/libpdfium.so");rejected("/original.pdf");
 rejected("/installed/libpdfium.so"+(char)0);rejected("/"+"x".repeat(4096)+"/libpdfium.so");
 engine[0]^=1;
 try{authenticate(engine);throw new AssertionError("accepted altered engine");}catch(IllegalStateException expected){count++;}
 for(int size:new int[]{0,20000001}){
  try{call("bytes",InputStream.class,new ByteArrayInputStream(new byte[size]));throw new AssertionError("accepted engine byte bound");}
  catch(IllegalStateException expected){count++;}
 }
 System.out.println(count+" actual Java installed-engine authentication assertions PASS; FD load remains Android-only");
}}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-cp',str(android),'-d',temp,*sources,str(probe)],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp+os.pathsep+str(android),'test.ProviderTest',str(Path(apk).resolve()),temp],check=True)

    def test_actual_session_owner_and_release_failures(self):
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        android=Path(os.environ['ANDROID_HOME'])/'platforms/android-35/android.jar'
        with tempfile.TemporaryDirectory(prefix='rtl-session-release-') as temp:
            folder=Path(temp)
            for name in ('PdfiumSession','PdfiumRasterLedger'):
                (folder/(name+'.java')).write_text((ROOT/'native'/(name+'.java.template')).read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (folder/'SessionTest.java').write_text('''package test;
import java.lang.reflect.*;
final class PdfiumEngine {
 static RuntimeException failure;
 static void ensure(){if(failure!=null)throw failure;}
}
final class PdfiumReaderCore {
 static int closes,releases;static RuntimeException closeFailure,releaseFailure;
 static long openStream(java.io.InputStream input,long bytes){throw new AssertionError("unexpected Android input read");}
 static int count(long token){throw new AssertionError();}
 static void close(long token){closes++;if(closeFailure!=null)throw closeFailure;}
 static void releaseEngine(){releases++;if(releaseFailure!=null)throw releaseFailure;}
}
public class SessionTest {
 static int count;static Field active;static Constructor<PdfiumSession> constructor;
 static void ok(boolean b){if(!b)throw new AssertionError("assertion "+count);count++;}
 static void reset()throws Exception{
  active.set(null,null);PdfiumEngine.failure=null;PdfiumReaderCore.closes=PdfiumReaderCore.releases=0;
  PdfiumReaderCore.closeFailure=PdfiumReaderCore.releaseFailure=null;
 }
 static PdfiumSession owner(long token)throws Exception{
  PdfiumSession value=constructor.newInstance(token,"relative.pdf","relative.pdf","hash",1,10L);
  active.set(null,value);return value;
 }
 public static void main(String[] args)throws Exception{
  active=PdfiumSession.class.getDeclaredField("active");active.setAccessible(true);
  constructor=PdfiumSession.class.getDeclaredConstructor(long.class,String.class,String.class,String.class,int.class,long.class);
  constructor.setAccessible(true);
  reset();RuntimeException original=new IllegalStateException("ensure failure");PdfiumEngine.failure=original;
  try{PdfiumSession.open("invalid",1);throw new AssertionError();}catch(Exception e){ok(e==original);}
  ok(PdfiumReaderCore.closes==0);ok(PdfiumReaderCore.releases==1);ok(active.get(null)==null);
  reset();try{PdfiumSession.open("invalid",1);throw new AssertionError();}catch(IllegalArgumentException expected){count++;}
  ok(PdfiumReaderCore.closes==0);ok(PdfiumReaderCore.releases==1);
  reset();PdfiumEngine.failure=original;RuntimeException release=new IllegalStateException("release failure");
  PdfiumReaderCore.releaseFailure=release;
  try{PdfiumSession.open("invalid",1);throw new AssertionError();}catch(Exception e){ok(e==original);ok(e.getSuppressed().length==1);ok(e.getSuppressed()[0]==release);}
  reset();PdfiumSession a=owner(1);
  try{PdfiumSession.open("invalid",1);throw new AssertionError();}catch(IllegalStateException expected){count++;}
  ok(PdfiumReaderCore.closes==0);ok(PdfiumReaderCore.releases==0);ok(a.current());ok(PdfiumSession.require("1")==a);
  a.close();ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);ok(!a.current());ok(active.get(null)==null);
  a.close();ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);
  try{PdfiumSession.require("1");throw new AssertionError();}catch(IllegalStateException expected){count++;}
  reset();PdfiumSession b=owner(2);a.close();ok(b.current());ok(PdfiumReaderCore.closes==0);ok(PdfiumReaderCore.releases==0);b.close();
  reset();PdfiumSession c=owner(3);RuntimeException close=new IllegalStateException("close failure");
  PdfiumReaderCore.closeFailure=close;PdfiumReaderCore.releaseFailure=release;
  try{c.close();throw new AssertionError();}catch(RuntimeException e){ok(e==close);ok(e.getSuppressed().length==1);ok(e.getSuppressed()[0]==release);}
  ok(active.get(null)==null);ok(!c.current());c.close();ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);
  reset();PdfiumSession d=owner(4);PdfiumReaderCore.releaseFailure=release;
  try{d.close();throw new AssertionError();}catch(RuntimeException e){ok(e==release);}
  ok(active.get(null)==null);d.close();ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);
  reset();PdfiumSession e=owner(5);e.fence();ok(!e.current());
  try{PdfiumSession.open("invalid",1);throw new AssertionError();}catch(IllegalStateException expected){count++;}
  ok(PdfiumReaderCore.releases==0);e.close();ok(PdfiumReaderCore.releases==1);
  System.out.println(count+" actual Session ownership/release assertions PASS; native dlclose is Android-only");
 }
}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-cp',str(android),'-d',temp,
                *[str(folder/name) for name in ('PdfiumSession.java','PdfiumRasterLedger.java','SessionTest.java')]],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp+os.pathsep+str(android),'test.SessionTest'],check=True)

    def test_actual_module_reports_failed_cleanup_without_success_receipt(self):
        home=Path(os.environ['JAVA_HOME'])/'bin';suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='rtl-module-release-') as temp:
            folder=Path(temp);bridge=folder/'com/facebook/react/bridge';bridge.mkdir(parents=True)
            stubs={
                'ReactApplicationContext':'public class ReactApplicationContext {}',
                'ReactContextBaseJavaModule':'public class ReactContextBaseJavaModule { public ReactContextBaseJavaModule(ReactApplicationContext c){} public String getName(){return "";} public void invalidate(){} }',
                'ReactMethod':'public @interface ReactMethod {}',
                'Promise':'public interface Promise {void resolve(Object value);void reject(String code,String message);void reject(String code,String message,Throwable error);}',
                'WritableMap':'public interface WritableMap {void putString(String name,String value);void putInt(String name,int value);}',
                'Arguments':'public class Arguments {public static WritableMap createMap(){return new WritableMap(){public void putString(String n,String v){}public void putInt(String n,int v){}};}}',
            }
            for name,body in stubs.items():(bridge/(name+'.java')).write_text('package com.facebook.react.bridge;'+body,encoding='utf-8')
            (folder/'PdfiumReaderModule.java').write_text((ROOT/'native/PdfiumReaderModule.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (folder/'ModuleTest.java').write_text('''package test;
import java.lang.reflect.*;import java.util.concurrent.*;import com.facebook.react.bridge.*;
final class PdfiumSession {
 static final ExecutorService QUEUE=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r);t.setUncaughtExceptionHandler((thread,error)->{});return t;});
 static PdfiumSession next;static Runnable duringOpen;String id="1",path="fixture.pdf",sha256="hash";int pageCount=1;long token=1;
 int closes;boolean closed;RuntimeException failure,verifyFailure;CountDownLatch closeEntered,closeContinue;
 static PdfiumSession open(String path,int count){if(duringOpen!=null)duringOpen.run();return next;}
 void fence(){}void verifySource(){if(verifyFailure!=null)throw verifyFailure;}
 void close(){if(closed)return;closed=true;closes++;
  if(closeEntered!=null){closeEntered.countDown();try{if(!closeContinue.await(5,TimeUnit.SECONDS))throw new AssertionError("close latch");}catch(InterruptedException e){throw new AssertionError(e);}}
  if(failure!=null)throw failure;}
}
final class PdfiumReaderCore {static RuntimeException failure;static String outline(long token){if(failure!=null)throw failure;return "[]";}}
public class ModuleTest {
 static int count;static Field owned;
 static class Result implements Promise {
  int resolved,rejected;Throwable error;String code;CountDownLatch done=new CountDownLatch(1);
  public void resolve(Object value){resolved++;done.countDown();}
  public void reject(String c,String m){reject(c,m,null);}
  public void reject(String c,String m,Throwable e){rejected++;code=c;error=e;done.countDown();}
  void await()throws Exception{ok(done.await(5,TimeUnit.SECONDS));ok(resolved+rejected==1);}
 }
 static void ok(boolean b){if(!b)throw new AssertionError("assertion "+count);count++;}
 static PdfiumReaderModule module(PdfiumSession s)throws Exception{
  PdfiumReaderModule m=new PdfiumReaderModule(new ReactApplicationContext());if(s!=null)owned.set(m,s);return m;
 }
 public static void main(String[] args)throws Exception{
  try{
   owned=PdfiumReaderModule.class.getDeclaredField("owned");owned.setAccessible(true);
   PdfiumSession retained=new PdfiumSession();PdfiumReaderModule existing=module(retained);Result duplicate=new Result();
   existing.open("fixture.pdf",1,duplicate);duplicate.await();ok(duplicate.rejected==1);ok("PDFIUM_OWNER".equals(duplicate.code));ok(owned.get(existing)==retained);ok(retained.closes==0);
   RuntimeException primary=new IllegalStateException("outline failure"),cleanup=new IllegalStateException("release failure");
   PdfiumSession a=new PdfiumSession();a.failure=cleanup;PdfiumSession.next=a;PdfiumReaderCore.failure=primary;
   PdfiumReaderModule m=module(null);Result open=new Result();m.open("fixture.pdf",1,open);open.await();
   ok(open.rejected==1);ok("PDFIUM_CLEANUP".equals(open.code));ok(open.error==primary);ok(primary.getSuppressed().length==1);ok(primary.getSuppressed()[0]==cleanup);ok(owned.get(m)==null);ok(a.closes==1);
   PdfiumReaderCore.failure=null;
   PdfiumSession retired=new PdfiumSession();retired.failure=cleanup;PdfiumSession.next=retired;PdfiumReaderModule retiring=module(null);
   PdfiumSession.duringOpen=()->retiring.invalidate();Result retirement=new Result();retiring.open("fixture.pdf",1,retirement);retirement.await();
   ok("PDFIUM_CLEANUP".equals(retirement.code));ok(retirement.error.getSuppressed().length==1);ok(retirement.error.getSuppressed()[0]==cleanup);ok(retired.closes==1);ok(owned.get(retiring)==null);PdfiumSession.duringOpen=null;
   PdfiumSession b=new PdfiumSession();b.failure=cleanup;m=module(b);Result close=new Result();m.close("1",false,close);close.await();
   ok(close.rejected==1);ok("PDFIUM_CLEANUP".equals(close.code));ok(close.error==cleanup);ok(owned.get(m)==null);ok(b.closes==1);
   Result repeated=new Result();m.close("1",false,repeated);repeated.await();ok(repeated.rejected==1);ok(repeated.resolved==0);ok("PDFIUM_CLEANUP".equals(repeated.code));
   PdfiumSession c=new PdfiumSession();RuntimeException source=new IllegalStateException("source changed");c.verifyFailure=source;c.failure=new IllegalStateException("cleanup");
   m=module(c);Result verify=new Result();m.close("1",true,verify);verify.await();ok("PDFIUM_CLEANUP".equals(verify.code));ok(verify.error==source);ok(source.getSuppressed().length==1);ok(owned.get(m)==null);
   repeated=new Result();m.close("1",false,repeated);repeated.await();ok(repeated.rejected==1);
   PdfiumSession d=new PdfiumSession();m=module(d);Result success=new Result();m.close("1",false,success);success.await();ok(success.resolved==1);
   repeated=new Result();m.close("1",false,repeated);repeated.await();ok(repeated.resolved==1);ok(d.closes==1);
   PdfiumSession sourceOnly=new PdfiumSession();sourceOnly.verifyFailure=source;m=module(sourceOnly);Result sourceResult=new Result();
   m.close("1",true,sourceResult);sourceResult.await();ok("PDFIUM_SOURCE".equals(sourceResult.code));ok(sourceOnly.closes==1);ok(owned.get(m)==null);
   PdfiumSession e=new PdfiumSession();e.failure=cleanup;m=module(e);m.invalidate();PdfiumSession.QUEUE.submit(()->{}).get(5,TimeUnit.SECONDS);
   ok(owned.get(m)==null);ok(e.closes==1);
   Result afterInvalid=new Result();m.close("1",false,afterInvalid);afterInvalid.await();ok("PDFIUM_CLEANUP".equals(afterInvalid.code));
   PdfiumSession concurrent=new PdfiumSession();concurrent.failure=cleanup;concurrent.closeEntered=new CountDownLatch(1);concurrent.closeContinue=new CountDownLatch(1);
   m=module(concurrent);Result first=new Result(),second=new Result();m.close("1",false,first);ok(concurrent.closeEntered.await(5,TimeUnit.SECONDS));
   m.close("1",false,second);concurrent.closeContinue.countDown();first.await();second.await();
   ok("PDFIUM_CLEANUP".equals(first.code));ok("PDFIUM_CLEANUP".equals(second.code));ok(concurrent.closes==1);ok(owned.get(m)==null);
   Result afterFailureOpen=new Result();m.open("fixture.pdf",1,afterFailureOpen);afterFailureOpen.await();ok("PDFIUM_CLEANUP".equals(afterFailureOpen.code));
   System.out.println(count+" actual Module cleanup/Promise/receipt assertions PASS; Session/native peers are controlled fakes");
  }finally{PdfiumSession.QUEUE.shutdownNow();}
 }
}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,
                *[str(path) for path in folder.rglob('*.java')]],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.ModuleTest'],check=True)


if __name__=='__main__':unittest.main()
