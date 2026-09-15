#include "collector_core.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr std::int64_t kCaptureBudgetNs = 20LL * 1000LL * 1000LL * 1000LL;
constexpr std::int64_t kChildCleanupGraceNs =
    1LL * 1000LL * 1000LL * 1000LL;
constexpr std::int64_t kHardProcessBudgetNs =
    22LL * 1000LL * 1000LL * 1000LL;
constexpr std::size_t kMaxPropertyBytes = 4096U;
constexpr std::size_t kMaxPackagePathBytes = 8192U;
constexpr std::size_t kMaxApkBytes = 32U * 1024U * 1024U;
constexpr char kPinnedFingerprint[] =
    "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
    "eng.supern.20260616.100032:user/release-keys";

struct CommandResult {
  std::string stdout_bytes;
  std::string stderr_bytes;
  int exit_code{-1};
};

struct FileIdentity {
  dev_t device{};
  ino_t inode{};
  off_t size{};
  mode_t mode{};
  uid_t uid{};
  gid_t gid{};
  std::int64_t mtime_sec{};
  std::int64_t mtime_nsec{};

  bool operator==(const FileIdentity &other) const {
    return device == other.device && inode == other.inode && size == other.size &&
           mode == other.mode && uid == other.uid && gid == other.gid &&
           mtime_sec == other.mtime_sec && mtime_nsec == other.mtime_nsec;
  }
};

timer_t watchdog_timer{};

void hard_timeout(int) {
  // Async-signal-safe and deliberately unconditional: this is the outer hard
  // bound for blocking filesystem/proc reads, normalization, child cleanup,
  // and a blocked downstream stdout consumer.
  _exit(70);
}

bool arm_hard_watchdog() {
  struct sigaction action {};
  action.sa_handler = hard_timeout;
  if (sigemptyset(&action.sa_mask) != 0 ||
      sigaction(SIGALRM, &action, nullptr) != 0)
    return false;
  sigset_t unblocked;
  if (sigemptyset(&unblocked) != 0 ||
      sigaddset(&unblocked, SIGALRM) != 0 ||
      sigprocmask(SIG_UNBLOCK, &unblocked, nullptr) != 0)
    return false;
  struct sigevent event {};
  event.sigev_notify = SIGEV_SIGNAL;
  event.sigev_signo = SIGALRM;
  if (timer_create(CLOCK_MONOTONIC, &event, &watchdog_timer) != 0)
    return false;
  struct itimerspec timeout {};
  timeout.it_value.tv_sec =
      static_cast<time_t>(kHardProcessBudgetNs / 1000000000LL);
  timeout.it_value.tv_nsec =
      static_cast<long>(kHardProcessBudgetNs % 1000000000LL);
  if (timer_settime(watchdog_timer, 0, &timeout, nullptr) != 0) {
    (void)timer_delete(watchdog_timer);
    return false;
  }
  return true;
}

bool monotonic_ns(std::int64_t *value) {
  struct timespec stamp {};
  if (clock_gettime(CLOCK_MONOTONIC, &stamp) != 0 || stamp.tv_sec < 0 ||
      stamp.tv_nsec < 0 || stamp.tv_nsec >= 1000000000L ||
      stamp.tv_sec > (std::numeric_limits<std::int64_t>::max() - stamp.tv_nsec) /
                         1000000000LL)
    return false;
  *value = static_cast<std::int64_t>(stamp.tv_sec) * 1000000000LL +
           static_cast<std::int64_t>(stamp.tv_nsec);
  return true;
}

bool mark_time(std::int64_t deadline, std::int64_t *last) {
  std::int64_t now = 0;
  if (!monotonic_ns(&now) || now < *last || now >= deadline) return false;
  *last = now;
  return true;
}

void close_if_open(int *descriptor) {
  if (*descriptor >= 0) {
    while (close(*descriptor) != 0 && errno == EINTR) {}
    *descriptor = -1;
  }
}

bool reap_after_kill(pid_t child, std::int64_t deadline) {
  if (child <= 0) return false;
  (void)kill(child, SIGKILL);
  for (;;) {
    int status = 0;
    const pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child || (waited < 0 && errno == ECHILD)) return true;
    if (waited < 0 && errno != EINTR) return false;
    std::int64_t now = 0;
    if (!monotonic_ns(&now) || now >= deadline) return false;
    const std::int64_t remaining = deadline - now;
    struct timespec pause {};
    pause.tv_nsec = static_cast<long>(
        std::min<std::int64_t>(remaining, 1000000LL));
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {}
  }
}

void kill_and_require_reaped(pid_t child, std::int64_t cleanup_deadline) {
  if (!reap_after_kill(child, cleanup_deadline)) {
    // Continuing after an unproven reap could leave a live or zombie evidence
    // producer. The outer watchdog remains armed and bounds this fail-closed
    // process termination path.
    _exit(70);
  }
}

bool set_nonblocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool append_pipe(int descriptor, std::size_t maximum, std::string *output,
                 bool *open) {
  std::array<char, 16384> buffer{};
  for (;;) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count > 0) {
      if (static_cast<std::size_t>(count) > maximum - output->size()) return false;
      output->append(buffer.data(), static_cast<std::size_t>(count));
      continue;
    }
    if (count == 0) {
      *open = false;
      return true;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
    return false;
  }
}

bool run_command(nppcap::FrozenCommand command,
                 std::size_t stdout_limit, std::int64_t deadline,
                 CommandResult *result) {
  const nppcap::FrozenCommandSpec *spec = nppcap::frozen_command_spec(command);
  if (spec == nullptr || spec->argc == 0U || spec->argc > spec->argv.size() ||
      stdout_limit == 0U ||
      deadline > std::numeric_limits<std::int64_t>::max() -
                     kChildCleanupGraceNs)
    return false;
  const std::int64_t cleanup_deadline = deadline + kChildCleanupGraceNs;
  std::array<char *, 5> argv{};
  for (std::size_t index = 0U; index != spec->argc; ++index) {
    if (spec->argv[index] == nullptr || spec->argv[index][0] == '\0' ||
        std::strlen(spec->argv[index]) > 4096U ||
        (index == 0U && spec->argv[index][0] != '/'))
      return false;
    argv[index] = const_cast<char *>(spec->argv[index]);
  }
  for (std::size_t index = spec->argc; index != spec->argv.size(); ++index)
    if (spec->argv[index] != nullptr) return false;
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  // The child's write endpoints must remain blocking. O_NONBLOCK is an open
  // file-description flag, so it is set only on the distinct parent read
  // endpoints after fork and after the parent closes both write endpoints.
  if (pipe2(stdout_pipe, O_CLOEXEC) != 0 ||
      pipe2(stderr_pipe, O_CLOEXEC) != 0) {
    close_if_open(&stdout_pipe[0]); close_if_open(&stdout_pipe[1]);
    close_if_open(&stderr_pipe[0]); close_if_open(&stderr_pipe[1]);
    return false;
  }
  const pid_t child = fork();
  if (child < 0) {
    close_if_open(&stdout_pipe[0]); close_if_open(&stdout_pipe[1]);
    close_if_open(&stderr_pipe[0]); close_if_open(&stderr_pipe[1]);
    return false;
  }
  if (child == 0) {
    const int null_input = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (null_input < 0 || dup2(null_input, STDIN_FILENO) < 0 ||
        dup2(stdout_pipe[1], STDOUT_FILENO) < 0 ||
        dup2(stderr_pipe[1], STDERR_FILENO) < 0)
      _exit(126);
    const long open_max_raw = sysconf(_SC_OPEN_MAX);
    const int open_max = open_max_raw > 0 && open_max_raw < 65536
                             ? static_cast<int>(open_max_raw) : 65536;
    for (int descriptor = 3; descriptor != open_max; ++descriptor)
      (void)close(descriptor);
    char path_env[] = "PATH=/system/bin";
    char locale_env[] = "LC_ALL=C";
    char *environment[] = {path_env, locale_env, nullptr};
    execve(argv[0], argv.data(), environment);
    _exit(127);
  }
  close_if_open(&stdout_pipe[1]);
  close_if_open(&stderr_pipe[1]);
  if (!set_nonblocking(stdout_pipe[0]) || !set_nonblocking(stderr_pipe[0])) {
    close_if_open(&stdout_pipe[0]);
    close_if_open(&stderr_pipe[0]);
    kill_and_require_reaped(child, cleanup_deadline);
    return false;
  }
  result->stdout_bytes.clear();
  result->stderr_bytes.clear();
  result->exit_code = -1;
  bool stdout_open = true, stderr_open = true, child_done = false;
  int child_status = 0;
  while (stdout_open || stderr_open || !child_done) {
    std::int64_t now = 0;
    if (!monotonic_ns(&now) || now >= deadline) {
      close_if_open(&stdout_pipe[0]); close_if_open(&stderr_pipe[0]);
      kill_and_require_reaped(child, cleanup_deadline);
      return false;
    }
    std::array<struct pollfd, 2> pollers{};
    nfds_t count = 0;
    if (stdout_open) pollers[count++] = {stdout_pipe[0], POLLIN | POLLHUP, 0};
    if (stderr_open) pollers[count++] = {stderr_pipe[0], POLLIN | POLLHUP, 0};
    const std::int64_t remaining_ns = deadline - now;
    const int timeout_ms = static_cast<int>(std::min<std::int64_t>(
        100, (remaining_ns + 999999LL) / 1000000LL));
    if (count != 0U) {
      const int polled = poll(pollers.data(), count, timeout_ms);
      if (polled < 0 && errno != EINTR) {
        close_if_open(&stdout_pipe[0]); close_if_open(&stderr_pipe[0]);
        kill_and_require_reaped(child, cleanup_deadline);
        return false;
      }
    }
    if (stdout_open &&
        !append_pipe(stdout_pipe[0], stdout_limit, &result->stdout_bytes,
                     &stdout_open)) {
      close_if_open(&stdout_pipe[0]); close_if_open(&stderr_pipe[0]);
      kill_and_require_reaped(child, cleanup_deadline);
      return false;
    }
    if (stderr_open &&
        !append_pipe(stderr_pipe[0], 65536U, &result->stderr_bytes,
                     &stderr_open)) {
      close_if_open(&stdout_pipe[0]); close_if_open(&stderr_pipe[0]);
      kill_and_require_reaped(child, cleanup_deadline);
      return false;
    }
    if (!child_done) {
      const pid_t waited = waitpid(child, &child_status, WNOHANG);
      if (waited == child) child_done = true;
      else if (waited < 0 && errno != EINTR) {
        close_if_open(&stdout_pipe[0]); close_if_open(&stderr_pipe[0]);
        kill_and_require_reaped(child, cleanup_deadline);
        return false;
      }
    }
  }
  close_if_open(&stdout_pipe[0]);
  close_if_open(&stderr_pipe[0]);
  if (!WIFEXITED(child_status)) return false;
  result->exit_code = WEXITSTATUS(child_status);
  return result->exit_code == 0 && result->stderr_bytes.empty();
}

bool single_line(const std::string &raw, std::size_t maximum,
                 std::string *line) {
  if (raw.empty() || raw.size() > maximum || raw.back() != '\n' ||
      raw.find('\n') != raw.size() - 1U || raw.find('\r') != std::string::npos ||
      raw.find('\0') != std::string::npos)
    return false;
  *line = raw.substr(0U, raw.size() - 1U);
  if (line->empty()) return false;
  for (unsigned char value : *line) {
    if (value < 0x21U || value > 0x7eU) return false;
  }
  return true;
}

bool run_line(nppcap::FrozenCommand command,
              std::int64_t deadline, std::size_t maximum,
              std::string *line) {
  CommandResult result;
  return run_command(command, maximum, deadline, &result) &&
         single_line(result.stdout_bytes, maximum, line);
}

bool read_bounded_fd(int descriptor, std::size_t maximum,
                     std::string *content) {
  content->clear();
  std::array<char, 16384> buffer{};
  for (;;) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count > 0) {
      if (static_cast<std::size_t>(count) > maximum - content->size())
        return false;
      content->append(buffer.data(), static_cast<std::size_t>(count));
      continue;
    }
    if (count == 0) return true;
    if (errno != EINTR) return false;
  }
}

bool read_bounded_file(const char *path, std::size_t maximum,
                       std::string *content) {
  const int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  struct stat status {};
  const bool regular = fstat(descriptor, &status) == 0 &&
                       S_ISREG(status.st_mode) && status.st_size >= 0 &&
                       static_cast<std::uint64_t>(status.st_size) <= maximum;
  const bool result = regular && read_bounded_fd(descriptor, maximum, content);
  int saved = errno;
  while (close(descriptor) != 0 && errno == EINTR) {}
  errno = saved;
  return result;
}

bool read_line_file(const char *path, std::size_t maximum, std::string *line) {
  std::string raw;
  return read_bounded_file(path, maximum, &raw) &&
         single_line(raw, maximum, line);
}

bool apk_identity(const std::string &path, FileIdentity *identity,
                  std::string *digest) {
  if (path.empty() || path.size() > 4096U || path.front() != '/' ||
      path.find("//") != std::string::npos ||
      path.find("/../") != std::string::npos ||
      path.find("/./") != std::string::npos ||
      path.rfind(".apk") != path.size() - 4U)
    return false;
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  struct stat status {};
  std::string content;
  bool ok = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
            status.st_size > 0 &&
            static_cast<std::uint64_t>(status.st_size) <= kMaxApkBytes &&
            read_bounded_fd(descriptor, kMaxApkBytes, &content);
  int saved = errno;
  while (close(descriptor) != 0 && errno == EINTR) {}
  errno = saved;
  if (!ok) return false;
  identity->device = status.st_dev;
  identity->inode = status.st_ino;
  identity->size = status.st_size;
  identity->mode = status.st_mode;
  identity->uid = status.st_uid;
  identity->gid = status.st_gid;
  identity->mtime_sec = status.st_mtim.tv_sec;
  identity->mtime_nsec = status.st_mtim.tv_nsec;
  *digest = nppcap::sha256_hex(content);
  std::fill(content.begin(), content.end(), '\0');
  return true;
}

bool package_path(std::int64_t deadline, std::string *path) {
  std::string line;
  if (!run_line(nppcap::FrozenCommand::kPackagePath, deadline,
                kMaxPackagePathBytes, &line))
    return false;
  constexpr char prefix[] = "package:";
  if (line.rfind(prefix, 0U) != 0U) return false;
  *path = line.substr(sizeof(prefix) - 1U);
  return !path->empty() && path->find(' ') == std::string::npos;
}

bool all_digits(const char *text) {
  if (text == nullptr || *text == '\0') return false;
  if (text[0] == '0' && text[1] != '\0') return false;
  for (const char *cursor = text; *cursor != '\0'; ++cursor)
    if (*cursor < '0' || *cursor > '9') return false;
  return true;
}

bool relevant_cmdline(const std::string &command, std::string *package,
                      bool *secondary) {
  for (const char *candidate : {nppcap::kForeignPackage, nppcap::kHostPackage}) {
    if (command == candidate) {
      *package = candidate;
      *secondary = false;
      return true;
    }
    const std::string prefix = std::string(candidate) + ':';
    if (command.rfind(prefix, 0U) == 0U) {
      *package = candidate;
      *secondary = true;
      return true;
    }
  }
  return false;
}

bool stat_start_ticks(const std::string &raw, std::string *ticks) {
  if (raw.empty() || raw.size() > 4096U || raw.find('\0') != std::string::npos)
    return false;
  const std::size_t close = raw.rfind(") ");
  if (close == std::string::npos || close + 3U >= raw.size()) return false;
  std::size_t begin = close + 2U;
  unsigned field = 3U;
  while (begin < raw.size()) {
    while (begin < raw.size() && raw[begin] == ' ') ++begin;
    std::size_t end = raw.find(' ', begin);
    if (end == std::string::npos) end = raw.find('\n', begin);
    if (end == std::string::npos) end = raw.size();
    if (field == 22U) {
      *ticks = raw.substr(begin, end - begin);
      if (ticks->empty() || (ticks->size() > 1U && ticks->front() == '0'))
        return false;
      for (char value : *ticks)
        if (value < '0' || value > '9') return false;
      return *ticks != "0";
    }
    ++field;
    begin = end + 1U;
  }
  return false;
}

bool read_at(int directory, const char *name, std::size_t maximum,
             std::string *content) {
  const int descriptor = openat(directory, name,
                                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  const bool result = read_bounded_fd(descriptor, maximum, content);
  int saved = errno;
  while (close(descriptor) != 0 && errno == EINTR) {}
  errno = saved;
  return result;
}

bool scan_processes(std::vector<nppcap::ProcessFact> *processes) {
  DIR *directory = opendir("/proc");
  if (directory == nullptr) return false;
  processes->clear();
  bool ok = true;
  std::size_t entries = 0U;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(directory);
    if (entry == nullptr) {
      if (errno != 0) ok = false;
      break;
    }
    if (++entries > 131072U) { ok = false; break; }
    if (!all_digits(entry->d_name)) continue;
    errno = 0;
    char *end = nullptr;
    const unsigned long raw_pid = strtoul(entry->d_name, &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' || raw_pid == 0UL ||
        raw_pid > nppcap::kMaxPid)
      continue;
    const int process_directory = openat(
        dirfd(directory), entry->d_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (process_directory < 0) {
      if (errno == ENOENT || errno == ESRCH) continue;
      ok = false; break;
    }
    std::string cmdline;
    if (!read_at(process_directory, "cmdline", 4096U, &cmdline)) {
      const int saved = errno;
      (void)close(process_directory);
      if (saved == ENOENT || saved == ESRCH) continue;
      ok = false; break;
    }
    const std::size_t nul = cmdline.find('\0');
    const std::string first = cmdline.substr(0U, nul);
    std::string package;
    bool secondary = false;
    if (!relevant_cmdline(first, &package, &secondary)) {
      (void)close(process_directory);
      continue;
    }
    if (secondary) { (void)close(process_directory); ok = false; break; }
    struct stat status {};
    std::string stat_raw, confirm_cmdline;
    if (fstat(process_directory, &status) != 0 ||
        !read_at(process_directory, "stat", 4096U, &stat_raw) ||
        !read_at(process_directory, "cmdline", 4096U, &confirm_cmdline) ||
        confirm_cmdline != cmdline || status.st_uid > 2147483647U) {
      (void)close(process_directory); ok = false; break;
    }
    (void)close(process_directory);
    std::string ticks;
    if (!stat_start_ticks(stat_raw, &ticks)) { ok = false; break; }
    processes->push_back({static_cast<std::uint32_t>(raw_pid), ticks,
                          static_cast<std::uint32_t>(status.st_uid), package});
  }
  (void)closedir(directory);
  if (!ok) return false;
  std::sort(processes->begin(), processes->end());
  if (processes->empty() || processes->size() > nppcap::kMaxRows) return false;
  bool host_found = false;
  for (std::size_t index = 0U; index != processes->size(); ++index) {
    if ((*processes)[index].package == nppcap::kHostPackage) host_found = true;
    if (index != 0U &&
        ((*processes)[index - 1U].pid == (*processes)[index].pid ||
         (*processes)[index - 1U].package == (*processes)[index].package))
      return false;
  }
  return host_found;
}

bool write_all_stdout(const std::vector<std::uint8_t> &wire) {
  std::size_t offset = 0U;
  while (offset != wire.size()) {
    const ssize_t count = write(STDOUT_FILENO, wire.data() + offset,
                                wire.size() - offset);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return false;
  }
  return true;
}

int collect() {
  std::int64_t started = 0;
  if (!monotonic_ns(&started) ||
      started > std::numeric_limits<std::int64_t>::max() - kCaptureBudgetNs)
    return 70;
  const std::int64_t deadline = started + kCaptureBudgetNs;
  std::int64_t last = started;

  std::string serial_before, fingerprint_before, boot_before;
  if (!run_line(nppcap::FrozenCommand::kSerial, deadline,
                kMaxPropertyBytes, &serial_before) ||
      !mark_time(deadline, &last) ||
      !run_line(nppcap::FrozenCommand::kFingerprint, deadline,
                kMaxPropertyBytes, &fingerprint_before) ||
      fingerprint_before != kPinnedFingerprint ||
      !mark_time(deadline, &last) ||
      !read_line_file("/proc/sys/kernel/random/boot_id", 128U, &boot_before) ||
      !mark_time(deadline, &last))
    return 70;

  std::string apk_path_before, apk_digest_before;
  FileIdentity apk_before;
  if (!package_path(deadline, &apk_path_before) ||
      !apk_identity(apk_path_before, &apk_before, &apk_digest_before) ||
      apk_digest_before != nppcap::kPinnedInstalledApkSha256 ||
      !mark_time(deadline, &last))
    return 70;

  std::vector<nppcap::ProcessFact> processes_before;
  if (!scan_processes(&processes_before) || !mark_time(deadline, &last))
    return 70;

  CommandResult activity, window, display;
  if (!run_command(nppcap::FrozenCommand::kActivity,
                   nppcap::kMaxActivityBytes, deadline, &activity) ||
      !mark_time(deadline, &last) ||
      !run_command(nppcap::FrozenCommand::kWindow,
                   nppcap::kMaxWindowBytes, deadline, &window) ||
      !mark_time(deadline, &last) ||
      !run_command(nppcap::FrozenCommand::kDisplay,
                   nppcap::kMaxDisplayBytes, deadline, &display) ||
      !mark_time(deadline, &last))
    return 70;

  std::vector<nppcap::ProcessFact> processes_after;
  std::string apk_path_after, apk_digest_after, boot_after;
  FileIdentity apk_after;
  if (!scan_processes(&processes_after) || processes_after != processes_before ||
      !mark_time(deadline, &last) ||
      !package_path(deadline, &apk_path_after) ||
      apk_path_after != apk_path_before ||
      !apk_identity(apk_path_after, &apk_after, &apk_digest_after) ||
      !(apk_after == apk_before) || apk_digest_after != apk_digest_before ||
      !mark_time(deadline, &last) ||
      !read_line_file("/proc/sys/kernel/random/boot_id", 128U, &boot_after) ||
      boot_after != boot_before || !mark_time(deadline, &last))
    return 70;

  std::string serial_after, fingerprint_after;
  if (!run_line(nppcap::FrozenCommand::kSerial, deadline,
                kMaxPropertyBytes, &serial_after) ||
      serial_after != serial_before || !mark_time(deadline, &last) ||
      !run_line(nppcap::FrozenCommand::kFingerprint, deadline,
                kMaxPropertyBytes, &fingerprint_after) ||
      fingerprint_after != fingerprint_before || !mark_time(deadline, &last))
    return 70;

  nppcap::CaptureInputs inputs;
  inputs.activity_raw = std::move(activity.stdout_bytes);
  inputs.window_raw = std::move(window.stdout_bytes);
  inputs.display_raw = std::move(display.stdout_bytes);
  inputs.serial = std::move(serial_before);
  inputs.boot_id = std::move(boot_before);
  inputs.installed_apk_sha256 = std::move(apk_digest_before);
  inputs.processes = std::move(processes_before);
  nppcap::CapturePayloads payloads;
  std::string error;
  if (!nppcap::normalize_capture(inputs, &payloads, &error) ||
      !mark_time(deadline, &last))
    return 70;
  std::vector<std::uint8_t> wire = nppcap::encode_wire(payloads, &error);
  if (wire.empty() || !mark_time(deadline, &last)) return 70;
  return write_all_stdout(wire) ? 0 : 71;
}

}  // namespace

int main(int argc, char **argv) {
  // The only accepted token is frozen in the PrivateADB service.  No token,
  // path, package, environment value, or stdin byte influences the capture.
  if (getuid() != 2000 || geteuid() != 2000) return 65;
  if (argc != 2 || argv == nullptr || argv[0] == nullptr || argv[1] == nullptr ||
      std::strcmp(argv[1], "--wire-v1") != 0)
    return 64;
  (void)signal(SIGPIPE, SIG_IGN);
  if (!arm_hard_watchdog()) return 70;
  try {
    return collect();
  } catch (...) {
    return 70;
  }
}
