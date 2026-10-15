// Same tested public API/transform/crop/UTF16/action code; no writer or save API.
// The production adapter admits bounded immutable original PDFs, not fixture IDs.
#define RTL_PDFIUM_READER 1
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_open Java_com_supernotertlreader_PdfiumReaderCore_open
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_close Java_com_supernotertlreader_PdfiumReaderCore_close
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_count Java_com_supernotertlreader_PdfiumReaderCore_count
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_outline Java_com_supernotertlreader_PdfiumReaderCore_outline
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_size Java_com_supernotertlreader_PdfiumReaderCore_size
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_point Java_com_supernotertlreader_PdfiumReaderCore_point
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_model Java_com_supernotertlreader_PdfiumReaderCore_model
#define Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_render Java_com_supernotertlreader_PdfiumReaderCore_render
#include "pdfium_provider.h"
#include "../probes/pdfium-native/native_core.cpp"
#include <dlfcn.h>

// Copy the authorized, Java-owned descriptor stream into ONE native snapshot.
// The fixed Java transfer buffer and DigestInputStream hash exactly these bytes;
// no full-file Java allocation, writable mapping, deferred source reads or cache.
extern "C" JNIEXPORT jlong JNICALL Java_com_supernotertlreader_PdfiumReaderCore_openStream(JNIEnv* env,jclass,jobject input,jlong length){
    std::lock_guard<std::mutex> guard(mutex);
    if(document || initialized){exception(env,"Document already open");return 0;}
    try{
        require(input && length>0 && length<=64LL*1024*1024,"Original PDF exceeds the bounded reader input");
        require(nextSession<INT64_MAX,"Session generation exhausted");
        auto type=env->FindClass("java/io/InputStream");
        require(type && !env->ExceptionCheck(),"Input stream class unavailable");
        auto read=env->GetMethodID(type,"read","([B)I");
        require(read && !env->ExceptionCheck(),"Input stream reader unavailable");
        auto block=env->NewByteArray(32768);
        require(block && !env->ExceptionCheck(),"Input transfer buffer allocation failed");
        bytes.resize(static_cast<size_t>(length));size_t offset=0;
        while(offset<bytes.size()){
            auto n=env->CallIntMethod(input,read,block);
            require(!env->ExceptionCheck(),"Input stream read failed");
            require(n>0 && n<=32768 && static_cast<size_t>(n)<=bytes.size()-offset,"PDF changed during read");
            env->GetByteArrayRegion(block,0,n,reinterpret_cast<jbyte*>(bytes.data()+offset));
            require(!env->ExceptionCheck(),"Input snapshot transfer failed");offset+=static_cast<size_t>(n);
        }
        auto eof=env->CallIntMethod(input,read,block);
        require(!env->ExceptionCheck() && eof==-1,"PDF changed during read");
        FPDF_InitLibrary();initialized=true;document=FPDF_LoadMemDocument64(bytes.data(),bytes.size(),nullptr);
        require(document,"PDF load failed");pageCount=FPDF_GetPageCount(document);
        require(pageCount>0 && pageCount<=10000,"Original page-count bound");
        currentSession=++nextSession;return currentSession;
    }catch(const std::exception& error){close();exception(env,error.what());return 0;}
}

// Verify the resolved API provider, not merely the similarly named APK entry.
extern "C" JNIEXPORT jstring JNICALL Java_com_supernotertlreader_PdfiumReaderCore_libraryPath(JNIEnv* env,jclass){
    std::lock_guard<std::mutex> guard(mutex);
    try{(void)rtl_provider::api();return env->NewStringUTF(rtl_provider::engineName.c_str());}
    catch(const std::exception& error){exception(env,error.what());return nullptr;}
}

extern "C" JNIEXPORT void JNICALL Java_com_supernotertlreader_PdfiumReaderCore_releaseEngine(JNIEnv* env,jclass){
    std::lock_guard<std::mutex> guard(mutex);
    try{require(!document && !initialized,"Cannot release an active PDFium document");rtl_provider::release();}
    catch(const std::exception& error){exception(env,error.what());}
}
