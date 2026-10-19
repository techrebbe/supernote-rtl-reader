"""Run the actual native library bridge; Android prefs/JSON/React peers controlled.

This checks bridge ordering, validation and commits, not Android JSON parsing or
hardware permissions. Actual bounded source reads are in test_pdfium_stream_input.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class NativeLibrary(unittest.TestCase):
    def test_real_android_react_compile_when_configured(self):
        sdk=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        react=os.environ.get('RTL_REACT_CLASSES_JAR')
        if not sdk or not react:
            self.skipTest('Normal package build compiles this bridge; set SDK and RTL_REACT_CLASSES_JAR for focused real-API compile')
        android=Path(sdk)/'platforms/android-35/android.jar'
        self.assertTrue(android.is_file());self.assertTrue(Path(react).is_file())
        suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='rtl-library-real-api-') as temp:
            folder=Path(temp)
            module=folder/'ReaderLibraryModule.java'
            module.write_text((ROOT/'native/ReaderLibraryModule.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            peer=folder/'PdfiumSession.java'
            peer.write_text('''package test;import java.util.concurrent.*;
final class PdfiumSession {static ExecutorService QUEUE=Executors.newSingleThreadExecutor();
 static String fingerprint(String path) throws Exception {return "";}}
''',encoding='utf-8')
            subprocess.run([str(Path(os.environ['JAVA_HOME'])/'bin'/('javac'+suffix)),
                '-encoding','UTF-8','-cp',os.pathsep.join([str(android),react]),'-d',temp,str(module),str(peer)],check=True)

    def test_actual_bridge_storage_and_retirement(self):
        sources={
            'android/content/SharedPreferences.java':'''package android.content;
public interface SharedPreferences {String getString(String k,String d);Editor edit();
 interface Editor {Editor putString(String k,String v);boolean commit();}}
''',
            'android/content/Context.java':'''package android.content;
public class Context {public static final int MODE_PRIVATE=0;}
''',
            'com/facebook/react/bridge/ReactApplicationContext.java':'''package com.facebook.react.bridge;
import android.content.*;
public class ReactApplicationContext extends Context {
 public SharedPreferences prefs;public String name;
 public SharedPreferences getSharedPreferences(String n,int mode){name=n;return prefs;}}
''',
            'com/facebook/react/bridge/ReactContextBaseJavaModule.java':'''package com.facebook.react.bridge;
public class ReactContextBaseJavaModule {public ReactContextBaseJavaModule(ReactApplicationContext c){}
 public String getName(){return "";}public void invalidate(){}}
''',
            'com/facebook/react/bridge/Promise.java':'''package com.facebook.react.bridge;
public interface Promise {void resolve(Object value);void reject(String c,String m,Throwable t);}
''',
            'com/facebook/react/bridge/ReactMethod.java':'''package com.facebook.react.bridge;
public @interface ReactMethod {}
''',
            'org/json/JSONArray.java':'''package org.json;
import java.util.*;
public class JSONArray {final List<Object> values=new ArrayList<>();
 public int length(){return values.size();}public JSONObject getJSONObject(int i){return (JSONObject)values.get(i);}
 public JSONArray put(Object v){values.add(v);return this;}}
''',
            'org/json/JSONObject.java':'''package org.json;
import java.util.*;
public class JSONObject {
 static final Map<String,JSONObject> encoded=new HashMap<>();static int next;
 final Map<String,Object> values=new HashMap<>();
 public JSONObject(){}public JSONObject(String s){
  if(s.equals("{\\"version\\":1,\\"entries\\":[]}")){put("version",1);put("entries",new JSONArray());}
  else {JSONObject source=encoded.get(s);if(source==null)throw new IllegalArgumentException("parse peer");values.putAll(source.values);}}
 public JSONObject put(String k,Object v){values.put(k,v);return this;}
 public Object get(String k){if(!values.containsKey(k))throw new IllegalArgumentException("missing");return values.get(k);}
 public int getInt(String k){return (int)getDouble(k);}public double getDouble(String k){return Double.parseDouble(get(k).toString());}
 public String getString(String k){return get(k).toString();}public JSONArray getJSONArray(String k){return (JSONArray)get(k);}
 public String toString(){String id="json-peer-"+(++next);encoded.put(id,this);return id;}}
''',
            'test/LibraryTest.java':r'''package test;
import android.content.*;import com.facebook.react.bridge.*;import org.json.*;import java.util.*;
class PdfiumSession {
 static final Queue QUEUE=new Queue();static String hash;static int reads;
 static String fingerprint(String path){reads++;if(hash==null)throw new IllegalStateException("unreadable");return hash;}
 static class Queue {final Deque<Runnable> work=new ArrayDeque<>();void execute(Runnable r){work.add(r);}
  void drain(){while(!work.isEmpty())work.remove().run();}}
}
class Prefs implements SharedPreferences,SharedPreferences.Editor {
 String raw,pending;boolean commit=true;int writes;
 public String getString(String k,String d){if(!k.equals("index"))throw new AssertionError("wrong namespace");return raw==null?d:raw;}
 public SharedPreferences.Editor edit(){return this;}public SharedPreferences.Editor putString(String k,String v){
  if(!k.equals("index"))throw new AssertionError("page preferences touched");pending=v;return this;}
 public boolean commit(){writes++;if(commit)raw=pending;return commit;}
}
class Result implements Promise {Object value;Throwable error;int replies;
 public void resolve(Object v){value=v;replies++;}public void reject(String c,String m,Throwable t){error=t;replies++;}}
public class LibraryTest {
 static int assertions;static void ok(boolean value){if(!value)throw new AssertionError("assertion "+assertions);assertions++;}
 static Result settled(Result r){ok(r.replies==0);PdfiumSession.QUEUE.drain();ok(r.replies==1);return r;}
 static JSONObject book(String path,Object count){return new JSONObject().put("filePath",path).put("sourceSha256","a".repeat(64)).put("pageCount",count);}
 static String index(Object version,JSONArray entries){return new JSONObject().put("version",version).put("entries",entries).toString();}
 static int size(Result r){return new JSONObject((String)r.value).getJSONArray("entries").length();}
 public static void main(String[] args){
  Prefs p=new Prefs();ReactApplicationContext c=new ReactApplicationContext();c.prefs=p;ReaderLibraryModule module=new ReaderLibraryModule(c);
  ok(c.name.equals("rtl_reader_favourites_v1"));ok(module.getName().equals("ReaderLibraryModule"));
  Result r=new Result();module.load(r);ok(size(settled(r))==0);ok(p.writes==0);
  r=new Result();module.put("/test.pdf","a".repeat(64),4,r);ok(size(settled(r))==1);ok(p.writes==1);
  r=new Result();module.put("/test.pdf","b".repeat(64),5,r);ok(size(settled(r))==1);ok(p.writes==2);
  PdfiumSession.hash="b".repeat(64);r=new Result();module.verify("/test.pdf",PdfiumSession.hash,r);ok(settled(r).value.equals(true));ok(PdfiumSession.reads==1);
  r=new Result();module.verify("/missing.pdf",PdfiumSession.hash,r);ok(settled(r).error!=null);ok(PdfiumSession.reads==1);
  PdfiumSession.hash=null;r=new Result();module.verify("/test.pdf","b".repeat(64),r);ok(settled(r).error!=null);ok(p.writes==2);
  PdfiumSession.hash="a".repeat(64);r=new Result();module.verify("/test.pdf","b".repeat(64),r);ok(settled(r).error!=null);
  for(String bad:new String[]{"test.pdf","/a/../test.pdf","/a/./test.pdf","/a\\b.pdf","/a\nb.pdf","/test.mark"}){
   r=new Result();module.put(bad,"a".repeat(64),4,r);ok(settled(r).error!=null);ok(p.writes==2);}
  for(double bad:new double[]{0,1.5,10001,Double.NaN}){r=new Result();module.put("/a.pdf","a".repeat(64),bad,r);ok(settled(r).error!=null);}
  String valid=p.raw;
  for(String corrupt:new String[]{"broken",index("1",new JSONArray()),index(1.5,new JSONArray()),
    index(1,new JSONArray().put(book("/a.pdf","4"))),index(1,new JSONArray().put(book("/a.pdf",4)).put(book("/a.pdf",4)))}){
   p.raw=corrupt;r=new Result();module.put("/new.pdf","a".repeat(64),4,r);ok(settled(r).error!=null);ok(p.writes==2);ok(p.raw.equals(corrupt));}
  JSONArray full=new JSONArray();for(int i=0;i<50;i++)full.put(book("/"+i+".pdf",4));p.raw=index(1,full);
  r=new Result();module.put("/new.pdf","a".repeat(64),4,r);ok(settled(r).error!=null);ok(p.writes==2);
  r=new Result();module.put("/0.pdf","b".repeat(64),4,r);ok(size(settled(r))==50);ok(p.writes==3);
  p.raw=valid;p.commit=false;r=new Result();module.remove("/test.pdf",r);ok(settled(r).error!=null);ok(p.raw.equals(valid));
  p.commit=true;r=new Result();module.remove("/test.pdf",r);ok(size(settled(r))==0);
  int writes=p.writes;r=new Result();module.put("/new.pdf","a".repeat(64),4,r);module.invalidate();ok(settled(r).error!=null);ok(p.writes==writes);
  System.out.println(assertions+" actual native library validation/queue/metadata assertions PASS; JSON/prefs peers controlled");
 }
}
'''
        }
        suffix='.exe' if os.name=='nt' else ''
        home=Path(os.environ['JAVA_HOME'])/'bin'
        with tempfile.TemporaryDirectory(prefix='rtl-library-native-') as temp:
            folder=Path(temp)
            sources['test/ReaderLibraryModule.java']=(ROOT/'native/ReaderLibraryModule.java.template').read_text().replace('__PACKAGE__','test')
            for name,source in sources.items():
                output=folder/name;output.parent.mkdir(parents=True,exist_ok=True);output.write_text(source,encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,*map(str,folder.rglob('*.java'))],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.LibraryTest'],check=True)


if __name__=='__main__':unittest.main()
