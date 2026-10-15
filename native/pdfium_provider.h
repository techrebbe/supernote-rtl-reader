// Private, authenticated, FD-owned provider. No engine mutation or default lookup.
#pragma once
#include <jni.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <limits>
#include <limits.h>
#include <cstdlib>
#include <mutex>
#include <stdexcept>
#include <string>
#include "pdfium_provider_generated.h"

namespace rtl_provider {
static Api currentApi;
static std::atomic<bool> ready{false};
static std::mutex bindMutex;
static void* engineHandle=nullptr;
static void* engineBase=nullptr;
static std::string engineName;
static bool poisoned=false;
const Api& api(){
    if(!ready.load(std::memory_order_acquire))throw std::runtime_error("PDFium provider not authenticated/bound");
    return currentApi;
}
static void throwJava(JNIEnv* env,const char* message){
    if(!env->ExceptionCheck())env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),message);
}
static void anchor(){}
static std::string candidatePath(){
    Dl_info info{};
    if(!dladdr(reinterpret_cast<const void*>(&anchor),&info) || !info.dli_fname)
        throw std::runtime_error("Wrapper location unavailable");
    std::string path(info.dli_fname),suffix="librtlpdfiumreader.so";
    if(path.empty() || path[0]!='/' || path.size()>4096 || path.size()<suffix.size() ||
       path.compare(path.size()-suffix.size(),suffix.size(),suffix)!=0)
        throw std::runtime_error("Unsupported private wrapper location");
    return path.substr(0,path.size()-suffix.size())+"libpdfium.so";
}
static void provider(const void* function,void* base,const std::string& name,const char* symbol){
    Dl_info info{};
    if(!function || !dladdr(function,&info) || info.dli_fbase!=base || !info.dli_fname || name!=info.dli_fname)
        throw std::runtime_error(std::string("Mixed PDFium binding ")+symbol+" expectedImage="+name+
            " actualImage="+(info.dli_fname?info.dli_fname:"unavailable")+" verifiedSnapshotSHA256="+kEngineSha256);
}
static void internalBindings(void* base,const std::string& name){
    uintptr_t start=reinterpret_cast<uintptr_t>(base);
    for(const auto& relocation:kInternalRelocations){
        bool readable=false;
        for(const auto& range:kReadable)
            if(range.end>=sizeof(void*) && range.start<=relocation.offset && relocation.offset<=range.end-sizeof(void*))readable=true;
        if(!readable || relocation.offset>std::numeric_limits<uintptr_t>::max()-start)
            throw std::runtime_error("PDFium internal relocation bounds");
        const void* target=nullptr;
        std::memcpy(&target,reinterpret_cast<const void*>(start+relocation.offset),sizeof(target));
        provider(target,base,name,relocation.symbol);
    }
}
// bindMutex is already held. Keep uncertain failed-admission teardown terminal.
static void discardRejectedReference(void* handle){
    if(dlclose(handle)!=0){engineHandle=handle;poisoned=true;}
}
static void bind(int descriptor,const std::string& label,const std::string& digest){
    std::lock_guard<std::mutex> lock(bindMutex);
    if(poisoned)throw std::runtime_error("PDFium provider teardown failed; no rebind");
    if(digest!=kEngineSha256)throw std::runtime_error("Unverified PDFium snapshot digest");
    struct stat status{};
    int flags=fcntl(descriptor,F_GETFL);
    if(flags<0 || (flags&O_ACCMODE)!=O_RDONLY || fstat(descriptor,&status)!=0 || !S_ISREG(status.st_mode) ||
       status.st_size!=static_cast<off_t>(kEngineBytes) || status.st_nlink<=0)
        throw std::runtime_error("PDFium requires the installed read-only exact library FD");
    if(label.empty() || label[0]!='/' || label.size()>4096 || label.find('\0')!=std::string::npos)
        throw std::runtime_error("Invalid private engine load label");
    std::string sibling=candidatePath();char canonical[PATH_MAX];struct stat named{};
    if(sibling.find("!/")!=std::string::npos || !realpath(sibling.c_str(),canonical) || label!=canonical ||
       lstat(canonical,&named)!=0 || !S_ISREG(named.st_mode) || named.st_dev!=status.st_dev ||
       named.st_ino!=status.st_ino || named.st_size!=status.st_size)
        throw std::runtime_error("Installed PDFium sibling FD/path mismatch");
    if(ready.load(std::memory_order_acquire))throw std::runtime_error("Previous engine mapping has not drained");
    // Map the same installed FD Java hashed, not a reopened pathname or cache
    // inode. FORCE_LOAD avoids name caching; it is not an isolation guarantee.
    android_dlextinfo extension{};
    extension.flags=ANDROID_DLEXT_USE_LIBRARY_FD|ANDROID_DLEXT_FORCE_LOAD;
    extension.library_fd=descriptor;
    void* handle=android_dlopen_ext(label.c_str(),RTLD_NOW|RTLD_LOCAL,&extension);
    if(!handle){const char* error=dlerror();throw std::runtime_error(std::string("Private PDFium FD load: ")+(error?error:"unavailable"));}
    try{
        Api proposed;
#define RTL_LOAD(name) dlerror(); proposed.fn_##name=reinterpret_cast<decltype(proposed.fn_##name)>(dlsym(handle,#name)); if(!proposed.fn_##name || dlerror())throw std::runtime_error("Missing private PDFium API: " #name);
        RTL_PDFIUM_API_TABLE(RTL_LOAD)
#undef RTL_LOAD
        // A defined non-IFUNC export is found first on the explicit handle's
        // root image. All other APIs and pinned internal FPDF slots must agree.
        Dl_info first{};
        if(!dladdr(reinterpret_cast<const void*>(proposed.fn_FPDF_InitLibrary),&first) || !first.dli_fbase || !first.dli_fname)
            throw std::runtime_error("Private PDFium image identity unavailable");
        if(label!=first.dli_fname)throw std::runtime_error("Private PDFium loaded image path mismatch");
#define RTL_CHECK(name) provider(reinterpret_cast<const void*>(proposed.fn_##name),first.dli_fbase,first.dli_fname,#name);
        RTL_PDFIUM_API_TABLE(RTL_CHECK)
#undef RTL_CHECK
        internalBindings(first.dli_fbase,first.dli_fname);
        currentApi=proposed;engineBase=first.dli_fbase;engineName=first.dli_fname;engineHandle=handle;
        ready.store(true,std::memory_order_release);
    }catch(...){
        // Failed admission still owns this dlopen reference. A failed release
        // poisons the provider; never retry or silently lose that reference.
        discardRejectedReference(handle);
        throw;
    }
    // Installation/update/re-extraction is excluded while this mapping is live.
    // Original-FD checks are not an ABA proof or same-process immutability seal.
}
// Caller holds the common native document mutex and proves no document/library
// state is alive. Never unmap underneath queued rendering/selection operations.
static void release(){
    std::lock_guard<std::mutex> lock(bindMutex);
    ready.store(false,std::memory_order_release);currentApi=Api{};
    if(poisoned)throw std::runtime_error("PDFium provider teardown failed; no retry");
    if(engineHandle && dlclose(engineHandle)!=0){poisoned=true;throw std::runtime_error("Private PDFium teardown failed");}
    engineHandle=nullptr;engineBase=nullptr;engineName.clear();
}
}

extern "C" JNIEXPORT jstring JNICALL Java_com_supernotertlreader_PdfiumReaderCore_candidatePath(JNIEnv* env,jclass){
    try{return env->NewStringUTF(rtl_provider::candidatePath().c_str());}
    catch(const std::exception& error){rtl_provider::throwJava(env,error.what());return nullptr;}
}
extern "C" JNIEXPORT void JNICALL Java_com_supernotertlreader_PdfiumReaderCore_bindEngine(JNIEnv* env,jclass,jint fd,jstring label,jstring digest){
    if(!label || !digest){rtl_provider::throwJava(env,"Missing authenticated engine identity");return;}
    const char* path=env->GetStringUTFChars(label,nullptr);
    if(!path)return;
    const char* hash=env->GetStringUTFChars(digest,nullptr);
    if(!hash){env->ReleaseStringUTFChars(label,path);return;}
    try{rtl_provider::bind(fd,path,hash);}
    catch(const std::exception& error){rtl_provider::throwJava(env,error.what());}
    env->ReleaseStringUTFChars(digest,hash);env->ReleaseStringUTFChars(label,path);
}
