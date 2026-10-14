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
#include "../probes/pdfium-native/native_core.cpp"
#include <dlfcn.h>

// Verify the resolved API provider, not merely the similarly named APK entry.
extern "C" JNIEXPORT jstring JNICALL Java_com_supernotertlreader_PdfiumReaderCore_libraryPath(JNIEnv* env,jclass){
    Dl_info info{};
    if(!dladdr(reinterpret_cast<const void*>(&FPDF_LoadMemDocument64),&info) || !info.dli_fname){
        exception(env,"PDFium provider identity unavailable");return nullptr;
    }
    return env->NewStringUTF(info.dli_fname);
}
