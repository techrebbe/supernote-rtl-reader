#include <android/log.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <jni.h>

namespace {

constexpr const char* kLogTag = "SN_SPREAD_PROBE_NATIVE";
constexpr const char* kTargetSymbol =
    "_Z36gridLineEraseTrailsAndSetTrailStatus"
    "RNSt6__ndk16vectorI14TrailContainerNS_9allocatorIS1_EEEERS1_"
    "RNS0_IiNS2_IiEEEERKdbibb";

constexpr std::ptrdiff_t kTrailRedrawWidth = 0x188;
constexpr std::ptrdiff_t kTrailRedrawHeight = 0x18c;
constexpr std::ptrdiff_t kTrailPenType = 0x1f4;

using HookFunType = int (*)(void* function, void* replacement, void** backup);
using UnhookFunType = int (*)(void* function);
using NativeOnModuleLoaded = void (*)(const char* name, void* handle);

struct NativeAPIEntries {
    std::uint32_t version;
    HookFunType hook_func;
    UnhookFunType unhook_func;
};

using NativeInit = NativeOnModuleLoaded (*)(const NativeAPIEntries* entries);

/*
 * C++ references are passed as pointers on arm64. The remaining scalar
 * parameters match the exported Supernote symbol's ABI.
 */
using GridLineErase = void (*)(
    void* current_page_trails,
    void* operation_trail,
    void* erased_trail_numbers,
    const double* scale,
    bool first_flag,
    int mode,
    bool second_flag,
    bool third_flag
);

std::atomic<bool> calibration_enabled{false};
std::atomic<int> hook_state{0};
HookFunType hook_function = nullptr;
GridLineErase original_grid_line_erase = nullptr;

int32_t& trail_int(void* trail, std::ptrdiff_t offset) {
    return *reinterpret_cast<int32_t*>(
        reinterpret_cast<std::uint8_t*>(trail) + offset
    );
}

bool ends_with(const char* value, const char* suffix) {
    if (value == nullptr || suffix == nullptr) {
        return false;
    }
    const std::size_t value_length = std::strlen(value);
    const std::size_t suffix_length = std::strlen(suffix);
    return value_length >= suffix_length
        && std::memcmp(
            value + value_length - suffix_length,
            suffix,
            suffix_length
        ) == 0;
}

void replacement_grid_line_erase(
    void* current_page_trails,
    void* operation_trail,
    void* erased_trail_numbers,
    const double* scale,
    bool first_flag,
    int mode,
    bool second_flag,
    bool third_flag
) {
    bool patched = false;
    int32_t original_width = 0;
    int32_t original_height = 0;

    if (calibration_enabled.load(std::memory_order_acquire)
        && operation_trail != nullptr) {
        const int32_t pen_type =
            trail_int(operation_trail, kTrailPenType);
        original_width =
            trail_int(operation_trail, kTrailRedrawWidth);
        original_height =
            trail_int(operation_trail, kTrailRedrawHeight);

        /*
         * Refuse every operation except the exact disposable left-page
         * landscape signature proven by the Frida experiment.
         */
        if (pen_type == 3
            && original_width == 932
            && original_height == 1243) {
            trail_int(operation_trail, kTrailRedrawWidth) = 1872;
            trail_int(operation_trail, kTrailRedrawHeight) = 2496;
            patched = true;
            __android_log_print(
                ANDROID_LOG_WARN,
                kLogTag,
                "eraser_redraw_patched from=932x1243 to=1872x2496"
            );
        }
    }

    original_grid_line_erase(
        current_page_trails,
        operation_trail,
        erased_trail_numbers,
        scale,
        first_flag,
        mode,
        second_flag,
        third_flag
    );

    if (patched) {
        trail_int(operation_trail, kTrailRedrawWidth) = original_width;
        trail_int(operation_trail, kTrailRedrawHeight) = original_height;
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "eraser_redraw_restored to=%dx%d",
            original_width,
            original_height
        );
    }
}

void on_library_loaded(const char* name, void* handle) {
    if (original_grid_line_erase != nullptr
        || name == nullptr
        || std::strstr(name, "/SupernoteDocument/") == nullptr
        || !ends_with(name, "/librecgnition.so")) {
        return;
    }

    void* target = dlsym(handle, kTargetSymbol);
    if (target == nullptr) {
        __android_log_print(
            ANDROID_LOG_ERROR,
            kLogTag,
            "eraser_hook_refused reason=symbol path=%s error=%s",
            name,
            dlerror()
        );
        return;
    }

    const int result = hook_function(
        target,
        reinterpret_cast<void*>(replacement_grid_line_erase),
        reinterpret_cast<void**>(&original_grid_line_erase)
    );
    if (result == 0 && original_grid_line_erase != nullptr) {
        hook_state.store(2, std::memory_order_release);
    }
    __android_log_print(
        result == 0 ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
        kLogTag,
        "eraser_hook_installed result=%d path=%s target=%p backup=%p",
        result,
        name,
        target,
        reinterpret_cast<void*>(original_grid_line_erase)
    );
}

}  // namespace

extern "C" JNIEXPORT void JNICALL
Java_com_techrebbe_supernote_spreadprobe_SpreadProbe_nativeSetCalibrationEnabled(
    JNIEnv*,
    jclass,
    jboolean enabled
) {
    calibration_enabled.store(enabled == JNI_TRUE, std::memory_order_release);
    __android_log_print(
        ANDROID_LOG_WARN,
        kLogTag,
        "calibration_enabled=%s",
        enabled == JNI_TRUE ? "true" : "false"
    );
}

extern "C" JNIEXPORT jint JNICALL
Java_com_techrebbe_supernote_spreadprobe_SpreadProbe_nativeGetHookState(
    JNIEnv*,
    jclass
) {
    return hook_state.load(std::memory_order_acquire);
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
jint JNI_OnLoad(JavaVM*, void*) {
    return JNI_VERSION_1_6;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries* entries) {
    if (entries == nullptr || entries->hook_func == nullptr) {
        return nullptr;
    }
    hook_function = entries->hook_func;
    hook_state.store(1, std::memory_order_release);
    __android_log_print(
        ANDROID_LOG_WARN,
        kLogTag,
        "native_init api_version=%u",
        entries->version
    );
    return on_library_loaded;
}
