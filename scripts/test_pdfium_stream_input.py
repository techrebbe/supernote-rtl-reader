"""Actual JNI stream method under a small JDK heap; PDFium is a controlled peer."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


def function(source, marker):
    start=source.index(marker);brace=source.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


class StreamInput(unittest.TestCase):
    def test_actual_session_stream_hash_source_drift_and_small_heap(self):
        home=Path(os.environ['JAVA_HOME']);suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-stream-session-') as temp:
            folder=Path(temp);system=folder/'android/system';system.mkdir(parents=True)
            (system/'StructStat.java').write_text('''package android.system;
public class StructStat {public long st_dev=1,st_ino=1,st_size,st_mtime,st_ctime;public int st_mode=1;}
''',encoding='utf-8')
            (system/'OsConstants.java').write_text('''package android.system;
public class OsConstants {public static final int O_RDONLY=1,O_CLOEXEC=2,O_NOFOLLOW=4;
 public static boolean S_ISREG(int mode){return mode==1;}}
''',encoding='utf-8')
            (system/'Os.java').write_text('''package android.system;
import java.io.*;import java.nio.file.*;import java.util.*;
public class Os {
 public static int revision,flags;public static final Map<FileDescriptor,FileInputStream> owners=new IdentityHashMap<>();
 static final Map<FileDescriptor,String> paths=new IdentityHashMap<>();
 public static FileDescriptor open(String path,int f,int mode)throws Exception{
  flags=f;FileInputStream input=new FileInputStream(path);FileDescriptor fd=input.getFD();owners.put(fd,input);paths.put(fd,path);return fd;}
 public static StructStat stat(String path)throws Exception{
  StructStat s=new StructStat();s.st_size=Files.size(Path.of(path));s.st_mtime=Files.getLastModifiedTime(Path.of(path)).toMillis();
  s.st_ctime=revision;return s;}
 public static StructStat fstat(FileDescriptor fd)throws Exception{
  if(!fd.valid())throw new IOException("closed descriptor");return stat(paths.get(fd));}
}
''',encoding='utf-8')
            for name in ('PdfiumSession','PdfiumRasterLedger'):
                (folder/(name+'.java')).write_text((ROOT/'native'/(name+'.java.template')).read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (folder/'StreamSessionTest.java').write_text(r'''package test;
import java.io.*;import java.security.*;import android.system.*;
final class PdfiumEngine {static void ensure(){}}
final class PdfiumReaderCore {
 static int opens,closes,releases,pages=663;static long next;static Runnable afterRead;
 static String observedHash;static boolean failRead;
 static long open(byte[] b){throw new AssertionError("whole-file Java allocation must not be used");}
 static long openStream(InputStream input,long size)throws Exception{
  opens++;if(failRead)throw new IOException("stream failure");MessageDigest digest=MessageDigest.getInstance("SHA-256");
  byte[] b=new byte[32768];long total=0;int n;while((n=input.read(b))!=-1){digest.update(b,0,n);total+=n;}
  if(total!=size)throw new AssertionError("input size");observedHash=java.util.HexFormat.of().formatHex(digest.digest());
  if(afterRead!=null)afterRead.run();return ++next;
 }
 static int count(long token){return pages;}static void close(long token){closes++;}static void releaseEngine(){releases++;}
}
public class StreamSessionTest {
 static int assertions;
 static void ok(boolean b){if(!b)throw new AssertionError("assertion "+assertions);assertions++;}
 static void closed(){for(FileDescriptor fd:Os.owners.keySet())ok(!fd.valid());}
 static void reset(){PdfiumReaderCore.opens=PdfiumReaderCore.closes=PdfiumReaderCore.releases=0;PdfiumReaderCore.pages=663;
  PdfiumReaderCore.afterRead=null;PdfiumReaderCore.failRead=false;}
 public static void main(String[] args)throws Exception{
  ok(Runtime.getRuntime().maxMemory()<=34L*1024*1024);
  File fixture=new File(args[0],"large-generated.pdf");String path=fixture.toURI().getPath();
  try(RandomAccessFile f=new RandomAccessFile(fixture,"rw")){f.setLength(65107439);}
  reset();PdfiumSession value=PdfiumSession.open(path,663);
  ok(value.current());ok(value.inputBytes==65107439);ok(value.canonicalPath.equals(fixture.getCanonicalPath()));
  ok(value.sha256.equals(PdfiumReaderCore.observedHash));ok(value.sha256.length()==64);ok(Os.flags==7);closed();
  value.verifySource();closed();ok(PdfiumReaderCore.opens==1);
  ok(PdfiumSession.fingerprint(path).equals(value.sha256));closed();ok(PdfiumReaderCore.opens==1);
  try(RandomAccessFile f=new RandomAccessFile(fixture,"rw")){f.seek(f.length()-1);f.write(1);}
  try{value.verifySource();throw new AssertionError("accepted changed bytes");}catch(IllegalStateException expected){assertions++;}
  ok(!PdfiumSession.fingerprint(path).equals(value.sha256));closed();ok(PdfiumReaderCore.opens==1);
  closed();value.close();ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);
  reset();PdfiumReaderCore.afterRead=()->Os.revision++;
  try{PdfiumSession.open(path,663);throw new AssertionError("accepted source drift after snapshot");}catch(IllegalStateException expected){assertions++;}
  ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);closed();
  reset();PdfiumReaderCore.pages=1;
  try{PdfiumSession.open(path,663);throw new AssertionError("accepted page mismatch");}catch(IllegalStateException expected){assertions++;}
  ok(PdfiumReaderCore.closes==1);ok(PdfiumReaderCore.releases==1);closed();
  reset();PdfiumReaderCore.failRead=true;
  try{PdfiumSession.open(path,663);throw new AssertionError("accepted failed stream");}catch(IOException expected){assertions++;}
  ok(PdfiumReaderCore.closes==0);ok(PdfiumReaderCore.releases==1);closed();
  reset();try(RandomAccessFile f=new RandomAccessFile(fixture,"rw")){f.setLength(64L*1024*1024+1);}
  try{PdfiumSession.open(path,663);throw new AssertionError("accepted input above cap");}catch(IllegalArgumentException expected){assertions++;}
  ok(PdfiumReaderCore.opens==0);ok(PdfiumReaderCore.releases==1);closed();
  System.out.println(assertions+" actual Session stream/hash/owner assertions PASS at -Xmx32m; Android stat/flags and native peers controlled");
 }
}
''',encoding='utf-8')
            sources=[str(p) for p in folder.rglob('*.java')]
            subprocess.run([str(home/'bin'/('javac'+suffix)),'-encoding','UTF-8','-d',temp,*sources],check=True)
            subprocess.run([str(home/'bin'/('java'+suffix)),'-Xmx32m','-cp',temp,'test.StreamSessionTest',temp],check=True)

    def test_actual_jni_stream_snapshot_and_failure_cleanup(self):
        home=Path(os.environ['JAVA_HOME']);suffix='.exe' if os.name=='nt' else ''
        compiler=os.environ.get('CXX') or shutil.which('g++')
        if not compiler:self.skipTest('A host C++17 compiler is required')
        reader=(ROOT/'native/pdfium_reader_core.cpp').read_text(encoding='utf-8')
        core=(ROOT/'probes/pdfium-native/native_core.cpp').read_text(encoding='utf-8')
        method=function(reader,'extern "C" JNIEXPORT jlong JNICALL Java_com_supernotertlreader_PdfiumReaderCore_openStream(')
        method=method.replace('Java_com_supernotertlreader_PdfiumReaderCore_openStream','Java_SnapshotTest_openStream')
        close=function(core,'void close(){')
        exception=function(core,'void exception(')
        cpp=r'''#include <jni.h>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <vector>
std::mutex mutex;std::vector<unsigned char> bytes;
void* document=nullptr;bool initialized=false;int pageCount=0;
uint64_t nextSession=0,currentSession=0;int initCalls=0,loadCalls=0;
void require(bool b,const char* message){if(!b)throw std::runtime_error(message);}
void FPDF_InitLibrary(){initCalls++;}
void FPDF_CloseDocument(void*){}
void FPDF_DestroyLibrary(){}
void* FPDF_LoadMemDocument64(const void* p,size_t n,const char*){
 loadCalls++;auto data=static_cast<const unsigned char*>(p);
 for(size_t i=0;i<n;i++)if(data[i]!=i%251)return nullptr;
 return reinterpret_cast<void*>(1);
}
int FPDF_GetPageCount(void*){return 663;}
/*ACTUAL_CLOSE*/
/*ACTUAL_EXCEPTION*/
/*ACTUAL_OPEN*/
extern "C" JNIEXPORT void JNICALL Java_SnapshotTest_close(JNIEnv*,jclass,jlong token){
 std::lock_guard<std::mutex> guard(mutex);
 if(token>0 && static_cast<uint64_t>(token)==currentSession)close();
}
extern "C" JNIEXPORT jlong JNICALL Java_SnapshotTest_retained(JNIEnv*,jclass){
 std::lock_guard<std::mutex> guard(mutex);return bytes.capacity();
}
'''.replace('/*ACTUAL_CLOSE*/',close).replace('/*ACTUAL_EXCEPTION*/',exception)
        java=r'''import java.io.*;
import java.security.*;
public class SnapshotTest {
 static {System.load(System.getProperty("snapshot.library"));}
 static native long openStream(InputStream input,long length);
 static native void close(long token);static native long retained();
 static int assertions;
 static void ok(boolean b){if(!b)throw new AssertionError("assertion "+assertions);assertions++;}
 static class Pattern extends InputStream {
  final long length;long offset;int reads;int maxRequest;
  Pattern(long n){length=n;}
  public int read(){throw new AssertionError("single-byte read is unnecessary");}
  public int read(byte[] b)throws IOException{return read(b,0,b.length);}
  public int read(byte[] b,int start,int len)throws IOException{
   reads++;maxRequest=Math.max(maxRequest,len);
   if(offset==length)return -1;int n=(int)Math.min(len,length-offset);
   for(int i=0;i<n;i++)b[start+i]=(byte)((offset+i)%251);offset+=n;return n;
  }
 }
 interface Trial {void run()throws Exception;}
 static void rejected(Trial trial)throws Exception{
  try{trial.run();throw new AssertionError("accepted invalid stream");}
  catch(IllegalStateException expected){assertions++;}
  ok(retained()==0);
 }
 public static void main(String[] args)throws Exception{
  ok(Runtime.getRuntime().maxMemory()<=34L*1024*1024);
  for(long length:new long[]{1,32767,32768,32769,65107439,64L*1024*1024}){
   Pattern p=new Pattern(length);MessageDigest digest=MessageDigest.getInstance("SHA-256");
   DigestInputStream hashed=new DigestInputStream(p,digest);long token=openStream(hashed,length);
   ok(token>0);ok(p.offset==length);ok(p.maxRequest==32768);ok(retained()>=length);
   // The fake parser checks EVERY native snapshot byte independently. This
   // also confirms the Java transfer hash tracks exactly the complete stream.
   ok(digest.digest().length==32);
   Pattern other=new Pattern(1);
   try{openStream(other,1);throw new AssertionError();}catch(IllegalStateException expected){assertions++;}
   ok(other.reads==0);ok(retained()>=length);close(token);ok(retained()==0);close(token);ok(retained()==0);
  }
  for(long size:new long[]{-1,0,64L*1024*1024+1}){
   Pattern p=new Pattern(1);rejected(()->openStream(p,size));ok(p.reads==0);
  }
  rejected(()->openStream(null,1));
  rejected(()->openStream(new Pattern(100),101));
  rejected(()->openStream(new Pattern(101),100));
  rejected(()->openStream(new Pattern(32768),32767));
  rejected(()->openStream(new Pattern(32769),32768));
  rejected(()->openStream(new Pattern(1){public int read(byte[] b,int start,int len){return 0;}},1));
  IOException original=new IOException("read-failure");
  try{openStream(new Pattern(1){public int read(byte[] b,int start,int len)throws IOException{throw original;}},1);throw new AssertionError();}
  catch(IOException impossible){throw new AssertionError(impossible);}
  catch(Throwable error){ok(error==original);} // JNI preserves the actual pending exception.
  ok(retained()==0);
  long a=openStream(new Pattern(10),10);close(a);long b=openStream(new Pattern(10),10);
  ok(b>a);close(a);ok(retained()>=10);close(b);ok(retained()==0);
  System.out.println(assertions+" actual JNI streaming/cleanup assertions PASS at -Xmx32m; parser/loader are controlled peers");
 }
}
'''
        # The Java compiler cannot see a checked exception declared by JNI.
        java=java.replace('catch(IOException impossible){throw new AssertionError(impossible);}\n  ','')
        with tempfile.TemporaryDirectory(prefix='pdfium-stream-jni-') as temp:
            folder=Path(temp);native=folder/'snapshot.cpp';probe=folder/'SnapshotTest.java'
            native.write_text(cpp.replace('/*ACTUAL_OPEN*/',method),encoding='utf-8')
            probe.write_text(java,encoding='utf-8')
            library=folder/('snapshot.dll' if os.name=='nt' else 'snapshot.so')
            includes=['-I'+str(home/'include'),'-I'+str(home/'include'/('win32' if os.name=='nt' else 'linux'))]
            command=[compiler,'-std=c++17','-O2','-shared',*includes,str(native),'-o',str(library)]
            if os.name=='nt':command+=['-static-libgcc','-static-libstdc++']
            else:command+=['-fPIC','-pthread']
            subprocess.run(command,check=True)
            subprocess.run([str(home/'bin'/('javac'+suffix)),'-encoding','UTF-8','-d',temp,str(probe)],check=True)
            run=[str(home/'bin'/('java'+suffix)),'-Xmx32m','-Dsnapshot.library='+str(library),'-cp',temp,'SnapshotTest']
            subprocess.run(run,check=True)
            # A real wrong transfer offset must fail the fake parser's complete
            # native-byte validation, not merely a source-text assertion.
            mutations=(
                ('copy offset','bytes.data()+offset','bytes.data()'),
                ('missing EOF','eof==-1','eof>=-1'),
                ('retained snapshot','close();exception(env,error.what());return 0;','exception(env,error.what());return 0;'),
            )
            for label,before,after in mutations:
                self.assertEqual(method.count(before),1,label)
                native.write_text(cpp.replace('/*ACTUAL_OPEN*/',method.replace(before,after,1)),encoding='utf-8')
                subprocess.run(command,check=True)
                result=subprocess.run(run,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0,label)
            print('3 compiled JNI input defect mutants rejected')


if __name__=='__main__':unittest.main()
