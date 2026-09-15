#ifndef NATIVE_PAGE_PLATFORM_COLLECTOR_CORE_HPP
#define NATIVE_PAGE_PLATFORM_COLLECTOR_CORE_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace nppcap {

constexpr std::size_t kMaxActivityBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxWindowBytes = 2U * 1024U * 1024U;
constexpr std::size_t kMaxProcessBytes = 256U * 1024U;
constexpr std::size_t kMaxDisplayBytes = 1024U * 1024U;
constexpr std::size_t kMaxWireBytes = 8U * 1024U * 1024U;
constexpr std::size_t kMaxRows = 256U;
constexpr std::uint32_t kMaxPid = 4U * 1024U * 1024U;

constexpr const char *kForeignPackage = "com.supernote.document";
constexpr const char *kHostPackage =
    "com.techrebbe.supernote.nativepagehost";
constexpr const char *kPinnedInstalledApkSha256 =
    "39abffb0c55ff0cacd5ab7b9917a529d2744684b43a96ade63c1f3374121617e";
constexpr const char *kPinnedReviewedUnsignedApkSha256 =
    "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178";
constexpr const char *kPinnedDexSha256 =
    "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6";
constexpr const char *kPinnedSignerCertSha256 =
    "a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67";
constexpr const char *kPinnedVersionName = "0.0.2-native-page-visual-only";
constexpr std::uint32_t kPinnedVersionCode = 2U;

enum class FrozenCommand : std::uint8_t {
  kSerial = 0U,
  kFingerprint = 1U,
  kPackagePath = 2U,
  kActivity = 3U,
  kWindow = 4U,
  kDisplay = 5U,
  kCount = 6U,
};

struct FrozenCommandSpec {
  std::size_t argc{};
  std::array<const char *, 4> argv{};
};

// Returns one of the six immutable subprocess command tuples used by the
// collector. Invalid enum values fail closed with nullptr.
const FrozenCommandSpec *frozen_command_spec(FrozenCommand command);

struct ProcessFact {
  std::uint32_t pid{};
  std::string start_ticks;
  std::uint32_t uid{};
  std::string package;

  bool operator==(const ProcessFact &other) const;
  bool operator<(const ProcessFact &other) const;
};

struct CaptureInputs {
  std::string activity_raw;
  std::string window_raw;
  std::string display_raw;
  std::string serial;
  std::string boot_id;
  std::string installed_apk_sha256;
  std::vector<ProcessFact> processes;
};

struct CapturePayloads {
  std::string activity;
  std::string window;
  std::string process;
  std::string display;
};

std::array<std::uint8_t, 32> sha256(const void *data, std::size_t size);
std::string sha256_hex(const void *data, std::size_t size);
std::string sha256_hex(const std::string &data);

// Converts the three pinned Android-11 dumpsys dialects into the exact text
// grammars consumed by native_page_visual_platform_authority.py.  It rejects
// missing, duplicate, contradictory, out-of-scope, or noncanonical evidence.
bool normalize_capture(const CaptureInputs &inputs, CapturePayloads *payloads,
                       std::string *error);

// Produces the frozen NPPCAP01 envelope.  The returned vector is empty on any
// invalid member or if the aggregate bound would be exceeded.
std::vector<std::uint8_t> encode_wire(const CapturePayloads &payloads,
                                      std::string *error);

}  // namespace nppcap

#endif
