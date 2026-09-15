#include "collector_core.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {

int checks = 0;

void require(bool condition, const char *message) {
  ++checks;
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    std::exit(1);
  }
}

void replace_once(std::string *text, const std::string &old_value,
                  const std::string &new_value) {
  const std::size_t position = text->find(old_value);
  require(position != std::string::npos, "mutation target exists");
  text->replace(position, old_value.size(), new_value);
}

nppcap::CaptureInputs valid_inputs() {
  nppcap::CaptureInputs inputs;
  inputs.serial = "SN078C10015092";
  inputs.boot_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  inputs.installed_apk_sha256 = nppcap::kPinnedInstalledApkSha256;
  inputs.processes = {
      {700U, "54321", 1000U, nppcap::kForeignPackage},
      {900U, "12345", 10123U, nppcap::kHostPackage},
  };
  inputs.activity_raw =
      "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
      "Display areas in focus order:\n"
      "Display #0 (activities from top to bottom):\n"
      "  Stack #90: type=standard mode=fullscreen\n"
      "    mResumedActivity: ActivityRecord{abc1234 u0 "
      "com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity t90}\n"
      "    * Task{def1234 #90 visible=true type=standard mode=fullscreen "
      "translucent=false A=10123:com.techrebbe.supernote.nativepagehost "
      "U=0 StackId=90 sz=1}\n"
      "      taskId=90 stackId=90\n"
      "      * Hist #0: ActivityRecord{abc1234 u0 "
      "com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity t90}\n"
      "          packageName=com.techrebbe.supernote.nativepagehost "
      "processName=com.techrebbe.supernote.nativepagehost\n"
      "          app=ProcessRecord{2083011 "
      "900:com.techrebbe.supernote.nativepagehost/10123}\n"
      "          mActivityComponent=com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity\n"
      "          baseDir=/data/app/native-page-host/base.apk\n"
      "          CurrentConfiguration={1.0 en_US 300dpi port winConfig={ "
      "mBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}}\n"
      "          state=RESUMED stopped=false delayedResume=false "
      "finishing=false\n"
      "          mVisibleRequested=true mVisible=true mClientVisible=true\n"
      "          reportedDrawn=true reportedVisible=true\n"
      "          nowVisible=true lastVisibleTime=-1s\n"
      "Display #5 (activities from top to bottom):\n"
      "  Stack #77: type=standard mode=fullscreen\n"
      "    mResumedActivity: ActivityRecord{11846f4 u0 "
      "com.supernote.document/.document.DocumentActivity t77}\n"
      "    * Task{66d8263 #77 visible=true type=standard mode=fullscreen "
      "translucent=false A=1000:com.supernote.document U=0 StackId=77 sz=1}\n"
      "      taskId=77 stackId=77\n"
      "      * Hist #0: ActivityRecord{11846f4 u0 "
      "com.supernote.document/.document.DocumentActivity t77}\n"
      "          packageName=com.supernote.document "
      "processName=com.supernote.document\n"
      "          app=ProcessRecord{2083012 700:com.supernote.document/1000}\n"
      "          mActivityComponent=com.supernote.document/"
      ".document.DocumentActivity\n"
      "          baseDir=/system_ext/app/SupernoteDocument/"
      "SupernoteDocument.apk\n"
      "          CurrentConfiguration={1.0 en_US 300dpi port winConfig={ "
      "mBounds=Rect(0, 0 - 1404, 1872) "
      "mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0} s.186}\n"
      "          state=RESUMED stopped=false delayedResume=false "
      "finishing=false\n"
      "          mVisibleRequested=true mVisible=true mClientVisible=true "
      "reportedDrawn=true reportedVisible=true\n"
      "          nowVisible=true lastVisibleTime=-2s\n";
  inputs.window_raw =
      "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
      "  mCurrentFocus=Window{aa00000 u0 "
      "com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity}\n"
      "  mCurrentFocus=Window{aa00001 u0 "
      "com.supernote.document/.document.DocumentActivity}\n"
      "  Window #8 Window{aa00000 u0 "
      "com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity}:\n"
      "    mSession=Session{a1b2c3 900:10123}\n"
      "    mOwnerUid=10123 package=com.techrebbe.supernote.nativepagehost\n"
      "    mDisplayId=0 stackId=90\n"
      "    mActivityRecord=ActivityRecord{abc1234 u0 "
      "com.techrebbe.supernote.nativepagehost/"
      "com.techrebbe.supernote.nativepagehost.NativePageHostActivity t90}\n"
      "    mFrame=[0,0][1404,1872]\n"
      "    mSurfaceFrame=[0,0][1404,1872]\n"
      "    mBufferSize=1404x1872\n"
      "    isVisible=true\n"
      "  Window #9 Window{aa00001 u0 "
      "com.supernote.document/.document.DocumentActivity}:\n"
      "    mSession=Session{a1b2c4 700:1000}\n"
      "    mOwnerUid=1000 package=com.supernote.document\n"
      "    mDisplayId=5 stackId=77\n"
      "    mActivityRecord=ActivityRecord{11846f4 u0 "
      "com.supernote.document/.document.DocumentActivity t77}\n"
      "    mFrame=[0,0][1404,1872]\n"
      "    mSurfaceFrame=[0,0][1404,1872]\n"
      "    mBufferSize=1404x1872\n"
      "    isVisible=true\n";
  inputs.display_raw =
      "DISPLAY MANAGER (dumpsys display)\n"
      "Logical Displays: size=2\n"
      "  Display 0:\n"
      "    mBaseDisplayInfo=DisplayInfo{\"Built-in Screen\", displayId 0, "
      "real 1404 x 1872, density 300, state ON, type BUILT_IN, "
      "uniqueId \"local:0\"}\n"
      "  Display 5:\n"
      "    mBaseDisplayInfo=DisplayInfo{\"NativePageVisualOnly-"
      "12345678-1234-4234-8234-123456789abc-1\", displayId 5, "
      "FLAG_DESTROY_CONTENT_ON_REMOVAL, FLAG_OWN_CONTENT_ONLY, "
      "real 1404 x 1872, density 300, state ON, type VIRTUAL, "
      "uniqueId \"virtual:com.techrebbe.supernote.nativepagehost,10123,5\", "
      "owner com.techrebbe.supernote.nativepagehost (uid 10123)}\n";
  return inputs;
}

std::uint32_t read_u32(const std::vector<std::uint8_t> &wire,
                       std::size_t offset) {
  return (static_cast<std::uint32_t>(wire[offset]) << 24U) |
         (static_cast<std::uint32_t>(wire[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(wire[offset + 2U]) << 8U) |
         static_cast<std::uint32_t>(wire[offset + 3U]);
}

bool verify_wire(const std::vector<std::uint8_t> &wire) {
  const std::array<std::uint8_t, 8> magic =
      {{'N', 'P', 'P', 'C', 'A', 'P', '0', '1'}};
  if (wire.size() < 8U + 4U * 37U + 33U ||
      !std::equal(magic.begin(), magic.end(), wire.begin())) return false;
  std::size_t offset = magic.size();
  for (std::uint8_t tag = 1U; tag <= 4U; ++tag) {
    if (wire.size() - offset < 37U || wire[offset] != tag) return false;
    const std::uint32_t size = read_u32(wire, offset + 1U);
    if (size == 0U || wire.size() - offset - 37U < size) return false;
    const auto digest = nppcap::sha256(wire.data() + offset + 37U, size);
    if (!std::equal(digest.begin(), digest.end(), wire.begin() + offset + 5U))
      return false;
    offset += 37U + size;
  }
  if (wire.size() - offset != 33U || wire[offset] != 0U) return false;
  const auto aggregate = nppcap::sha256(wire.data(), offset);
  return std::equal(aggregate.begin(), aggregate.end(),
                    wire.begin() + offset + 1U);
}

void expect_rejected(nppcap::CaptureInputs inputs, const char *label) {
  nppcap::CapturePayloads payloads;
  std::string error;
  require(!nppcap::normalize_capture(inputs, &payloads, &error), label);
  require(!error.empty(), "rejection has an internal diagnostic");
}

std::vector<std::uint8_t> valid_wire() {
  nppcap::CapturePayloads payloads;
  std::string error;
  const bool normalized = nppcap::normalize_capture(valid_inputs(), &payloads,
                                                     &error);
  if (!normalized) std::cerr << "normalize-error: " << error << '\n';
  require(normalized, "valid capture normalizes");
  require(payloads.activity.rfind(
              "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n", 0U)
              == 0U, "activity header is exact");
  require(payloads.window.rfind(
              "WINDOW MANAGER WINDOWS (dumpsys window windows)\n", 0U) == 0U,
          "window header is exact");
  require(payloads.process.find(
              "NATIVE PAGE PROCESS FACTS (private-adb-platform-v1)\n") == 0U,
          "process header is exact");
  require(payloads.display.rfind(
              "DISPLAY MANAGER DISPLAYS (dumpsys display)\n", 0U) == 0U,
          "display header is exact");
  require(payloads.display.find(
              "flags=DESTROY_CONTENT_ON_REMOVAL,OWN_CONTENT_ONLY,PUBLIC\n") !=
              std::string::npos, "display flags are canonical");
  require(payloads.display.find("uniqueId=sha256:") != std::string::npos,
          "unsafe raw unique ID is digest-bound");
  std::vector<std::uint8_t> wire = nppcap::encode_wire(payloads, &error);
  require(!wire.empty(), "valid wire encodes");
  require(verify_wire(wire), "valid wire framing and digests verify");
  return wire;
}

void mutations() {
  {
    auto value = valid_inputs();
    value.activity_raw.pop_back();
    expect_rejected(std::move(value), "unterminated ActivityManager rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.activity_raw, "reportedDrawn=true reportedVisible=true\n",
                 "reportedDrawn=true reportedVisible=true\n"
                 "          reportedDrawn=true\n");
    expect_rejected(std::move(value), "duplicate visibility rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.activity_raw, "900:com.techrebbe", "901:com.techrebbe");
    expect_rejected(std::move(value), "borrowed ActivityManager PID rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.activity_raw,
                 "A=10123:com.techrebbe.supernote.nativepagehost ",
                 "A=10123:com.example.unrelated ");
    expect_rejected(std::move(value),
                    "scoped activity hidden below unrelated task header rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.window_raw, "mOwnerUid=10123", "mOwnerUid=10124");
    expect_rejected(std::move(value), "WindowManager owner mismatch rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(
        &value.window_raw,
        "Window #8 Window{aa00000 u0 com.techrebbe.supernote.nativepagehost/"
        "com.techrebbe.supernote.nativepagehost.NativePageHostActivity}:\n",
        "Window #8 Window{aa00000 u0 com.example.unrelated/.Other}:\n");
    expect_rejected(std::move(value),
                    "scoped window hidden below unrelated header rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.window_raw,
                 "  mCurrentFocus=Window{aa00001 u0 ",
                 "  mCurrentFocus=Window{aa00001 u0 "
                 "com.supernote.document/.document.DocumentActivity}\n"
                 "  mCurrentFocus=Window{aa00001 u0 ");
    expect_rejected(std::move(value), "duplicate relevant focus rejects");
  }
  {
    auto value = valid_inputs();
    replace_once(&value.display_raw, "Display 5:\n", "Display 5:\n  Display 5:\n");
    expect_rejected(std::move(value), "ambiguous display rejects");
  }
  {
    auto value = valid_inputs();
    value.processes.push_back(
        {901U, "12346", 10123U, nppcap::kHostPackage});
    expect_rejected(std::move(value), "duplicate package process rejects");
  }
  {
    auto value = valid_inputs();
    value.serial = "bad serial";
    expect_rejected(std::move(value), "invalid serial rejects");
  }
  {
    auto value = valid_inputs();
    value.boot_id[0] = 'A';
    expect_rejected(std::move(value), "noncanonical boot ID rejects");
  }
  {
    auto value = valid_inputs();
    value.installed_apk_sha256[0] = '0';
    expect_rejected(std::move(value), "wrong installed APK rejects");
  }
}

void frozen_commands() {
  const std::array<std::vector<std::string>, 6> expected = {{
      {"/system/bin/getprop", "ro.serialno"},
      {"/system/bin/getprop", "ro.build.fingerprint"},
      {"/system/bin/cmd", "package", "path", nppcap::kHostPackage},
      {"/system/bin/dumpsys", "activity", "activities"},
      {"/system/bin/dumpsys", "window", "windows"},
      {"/system/bin/dumpsys", "display"},
  }};
  for (std::size_t index = 0U; index != expected.size(); ++index) {
    const auto *spec = nppcap::frozen_command_spec(
        static_cast<nppcap::FrozenCommand>(index));
    require(spec != nullptr, "frozen command exists");
    require(spec->argc == expected[index].size(),
            "frozen command cardinality is exact");
    for (std::size_t argument = 0U; argument != spec->argv.size(); ++argument) {
      if (argument < spec->argc) {
        require(spec->argv[argument] != nullptr &&
                    expected[index][argument] == spec->argv[argument],
                "frozen command argument is exact");
      } else {
        require(spec->argv[argument] == nullptr,
                "frozen command has no trailing argument authority");
      }
    }
  }
  require(nppcap::frozen_command_spec(
              static_cast<nppcap::FrozenCommand>(6U)) == nullptr,
          "first mutated command ID rejects");
  require(nppcap::frozen_command_spec(
              static_cast<nppcap::FrozenCommand>(255U)) == nullptr,
          "out-of-range command ID rejects");
}

}  // namespace

int main(int argc, char **argv) {
  require(nppcap::sha256_hex("", 0U) ==
              "e3b0c44298fc1c149afbf4c8996fb924"
              "27ae41e4649b934ca495991b7852b855",
          "SHA-256 empty vector");
  require(nppcap::sha256_hex("abc", 3U) ==
              "ba7816bf8f01cfea414140de5dae2223"
              "b00361a396177a9cb410ff61f20015ad",
          "SHA-256 abc vector");
  std::vector<std::uint8_t> wire = valid_wire();
  std::vector<std::uint8_t> changed = wire;
  changed[changed.size() / 2U] ^= 1U;
  require(!verify_wire(changed), "one-bit payload mutation rejects");
  changed = wire;
  changed.back() ^= 1U;
  require(!verify_wire(changed), "aggregate digest mutation rejects");
  frozen_commands();
  mutations();
  if (argc == 2 && std::strcmp(argv[1], "--emit-wire") == 0) {
#ifdef _WIN32
    require(_setmode(_fileno(stdout), _O_BINARY) != -1,
            "fixture stdout enters binary mode");
#endif
    std::cout.write(reinterpret_cast<const char *>(wire.data()),
                    static_cast<std::streamsize>(wire.size()));
    return std::cout.good() ? 0 : 1;
  }
  require(argc == 1, "test accepts only optional --emit-wire");
  std::cout << "PASS collector_core_test checks=" << checks << '\n';
  return 0;
}
