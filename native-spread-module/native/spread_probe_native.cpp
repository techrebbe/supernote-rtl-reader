#include <android/log.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <jni.h>

namespace {

constexpr const char* kLogTag = "SN_SPREAD_PROBE_NATIVE";
constexpr const char* kGridLineTargetSymbol =
    "_Z36gridLineEraseTrailsAndSetTrailStatus"
    "RNSt6__ndk16vectorI14TrailContainerNS_9allocatorIS1_EEEERS1_"
    "RNS0_IiNS2_IiEEEERKdbibb";
constexpr const char* kRegularTargetSymbol =
    "_Z10eraseTrailR14TrailContainerRNSt6__ndk16vectorIS_NS1_"
    "9allocatorIS_EEEERNS2_IiNS3_IiEEEES6_i";

constexpr std::ptrdiff_t kTrailRedrawWidth = 0x188;
constexpr std::ptrdiff_t kTrailRedrawHeight = 0x18c;
constexpr std::ptrdiff_t kTrailPenType = 0x1f4;
constexpr std::ptrdiff_t kTrailPenColor = 0x1f8;

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
using RegularErase = int (*)(
    void* operation_trail,
    void* current_page_trails,
    void* erased_trail_numbers,
    void* affected_trail_numbers,
    int mode
);

std::atomic<bool> calibration_enabled{false};
std::atomic<int> hook_state{0};
std::atomic<bool> grid_hook_attempted{false};
std::atomic<bool> regular_hook_attempted{false};
std::atomic<bool> grid_hook_installed{false};
std::atomic<bool> regular_hook_installed{false};
HookFunType hook_function = nullptr;
std::atomic<GridLineErase> original_grid_line_erase{nullptr};
std::atomic<RegularErase> original_regular_erase{nullptr};

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
    GridLineErase original = original_grid_line_erase.load(
        std::memory_order_acquire
    );
    if (original == nullptr) {
        return;
    }
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
        }
    }

    original(
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
    }
}

int replacement_regular_erase(
    void* operation_trail,
    void* current_page_trails,
    void* erased_trail_numbers,
    void* affected_trail_numbers,
    int mode
) {
    RegularErase original = original_regular_erase.load(
        std::memory_order_acquire
    );
    if (original == nullptr) {
        return 0;
    }
    bool patched = false;
    int32_t original_width = 0;
    int32_t original_height = 0;

    if (calibration_enabled.load(std::memory_order_acquire)
        && operation_trail != nullptr) {
        const int32_t pen_type =
            trail_int(operation_trail, kTrailPenType);
        const int32_t pen_color =
            trail_int(operation_trail, kTrailPenColor);
        original_width =
            trail_int(operation_trail, kTrailRedrawWidth);
        original_height =
            trail_int(operation_trail, kTrailRedrawHeight);

        /*
         * The document library's byte and bit erasers both construct their
         * hit-test image directly from these redraw dimensions. Refuse every
         * operation except the exact disposable spread regular-eraser
         * signature established by the dual Java/native trace.
         */
        if (pen_type == 16
            && pen_color == 255
            && original_width == 932
            && original_height == 1243) {
            trail_int(operation_trail, kTrailRedrawWidth) = 1872;
            trail_int(operation_trail, kTrailRedrawHeight) = 2496;
            patched = true;
        }
    }

    const int result = original(
        operation_trail,
        current_page_trails,
        erased_trail_numbers,
        affected_trail_numbers,
        mode
    );

    if (patched) {
        trail_int(operation_trail, kTrailRedrawWidth) = original_width;
        trail_int(operation_trail, kTrailRedrawHeight) = original_height;
    }
    return result;
}

void on_library_loaded(const char* name, void* handle) {
    if (name == nullptr
        || std::strstr(name, "/SupernoteDocument/") == nullptr
        || !ends_with(name, "/librecgnition.so")) {
        return;
    }

    if (!grid_hook_installed.load(std::memory_order_acquire)
        && !grid_hook_attempted.exchange(
            true,
            std::memory_order_acq_rel
        )) {
        void* target = dlsym(handle, kGridLineTargetSymbol);
        if (target == nullptr) {
            grid_hook_attempted.store(false, std::memory_order_release);
            __android_log_print(
                ANDROID_LOG_ERROR,
                kLogTag,
                "grid_eraser_hook_refused reason=symbol path=%s error=%s",
                name,
                dlerror()
            );
        } else {
            void* backup = nullptr;
            const int result = hook_function(
                target,
                reinterpret_cast<void*>(replacement_grid_line_erase),
                &backup
            );
            GridLineErase original = reinterpret_cast<GridLineErase>(backup);
            const bool installed = result == 0
                && original != nullptr;
            if (installed) {
                original_grid_line_erase.store(
                    original,
                    std::memory_order_release
                );
            }
            grid_hook_installed.store(
                installed,
                std::memory_order_release
            );
            // Retry only a contract-clean installer failure. A zero result
            // with no backup (or a nonzero result that still supplied one)
            // is ambiguous: the target may already be patched, so a second
            // installation could chain or corrupt the hook.
            if (!installed && result != 0 && backup == nullptr) {
                grid_hook_attempted.store(false, std::memory_order_release);
            }
            __android_log_print(
                installed ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
                kLogTag,
                "grid_eraser_hook_installed result=%d path=%s "
                "target=%p backup=%p",
                result,
                name,
                target,
                backup
            );
        }
    }

    if (!regular_hook_installed.load(std::memory_order_acquire)
        && !regular_hook_attempted.exchange(
            true,
            std::memory_order_acq_rel
        )) {
        void* target = dlsym(handle, kRegularTargetSymbol);
        if (target == nullptr) {
            regular_hook_attempted.store(false, std::memory_order_release);
            __android_log_print(
                ANDROID_LOG_ERROR,
                kLogTag,
                "regular_eraser_hook_refused reason=symbol path=%s error=%s",
                name,
                dlerror()
            );
        } else {
            void* backup = nullptr;
            const int result = hook_function(
                target,
                reinterpret_cast<void*>(replacement_regular_erase),
                &backup
            );
            RegularErase original = reinterpret_cast<RegularErase>(backup);
            const bool installed = result == 0
                && original != nullptr;
            if (installed) {
                original_regular_erase.store(
                    original,
                    std::memory_order_release
                );
            }
            regular_hook_installed.store(
                installed,
                std::memory_order_release
            );
            if (!installed && result != 0 && backup == nullptr) {
                regular_hook_attempted.store(false, std::memory_order_release);
            }
            __android_log_print(
                installed ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
                kLogTag,
                "regular_eraser_hook_installed result=%d path=%s "
                "target=%p backup=%p",
                result,
                name,
                target,
                backup
            );
        }
    }

    if (grid_hook_installed.load(std::memory_order_acquire)
        && regular_hook_installed.load(std::memory_order_acquire)) {
        hook_state.store(2, std::memory_order_release);
    }
    __android_log_print(
        hook_state.load(std::memory_order_acquire) == 2
            ? ANDROID_LOG_WARN : ANDROID_LOG_ERROR,
        kLogTag,
        "eraser_hooks_ready ready=%d path=%s grid=%p regular=%p",
        hook_state.load(std::memory_order_acquire) == 2 ? 1 : 0,
        name,
        reinterpret_cast<void*>(original_grid_line_erase.load(
            std::memory_order_acquire
        )),
        reinterpret_cast<void*>(original_regular_erase.load(
            std::memory_order_acquire
        ))
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
