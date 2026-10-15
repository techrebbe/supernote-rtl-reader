"""Private-provider ELF controls and actual Java input authentication, offline only."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
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
 try{call("snapshot",String.class,origin);throw new AssertionError("accepted unsupported input");}
 catch(IllegalStateException expected){count++;}
}
public static void main(String[] args)throws Exception{
 String apk=new File(args[0]).toURI().getPath();
 byte[] engine=(byte[])call("snapshot",String.class,apk+"!/lib/arm64-v8a/libpdfium.so");
 ok(engine.length==6573320);
 ok(call("digest",byte[].class,engine).equals("e6b7257b3905152dab64c79f7a4a570693e11ccb740e92e4d3b89c28df6fcbbb"));
 rejected(apk+"!/lib/armeabi-v7a/libpdfium.so");rejected(apk+"!/other.so");rejected("relative/libpdfium.so");rejected("/original.pdf");
 File wrong=new File(args[1],"wrong.npk");
 try(ZipOutputStream zip=new ZipOutputStream(new FileOutputStream(wrong))){
  zip.putNextEntry(new ZipEntry("lib/arm64-v8a/libpdfium.so"));engine[0]^=1;zip.write(engine);zip.closeEntry();
 }
 rejected(wrong.toURI().getPath()+"!/lib/arm64-v8a/libpdfium.so");
 for(int size:new int[]{0,20000001}){
  try{call("bytes",InputStream.class,new ByteArrayInputStream(new byte[size]));throw new AssertionError("accepted engine byte bound");}
  catch(IllegalStateException expected){count++;}
 }
 System.out.println(count+" actual Java engine authentication assertions PASS; FD load remains Android-only");
}}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-cp',str(android),'-d',temp,*sources,str(probe)],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp+os.pathsep+str(android),'test.ProviderTest',str(Path(apk).resolve()),temp],check=True)


if __name__=='__main__':unittest.main()
