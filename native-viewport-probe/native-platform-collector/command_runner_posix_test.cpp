// Linux/WSL behavioral test for the exact production subprocess runner.
#define main nppcap_collector_production_main
#include "native_page_platform_collector.cpp"
#undef main

#include <chrono>
#include <iostream>

namespace {

int wrapper_mode = 0;
constexpr std::size_t kLargeOutputBytes = 1024U * 1024U;

[[noreturn]] void child_exit(int status) { _exit(status); }

}  // namespace

extern "C" int __wrap_execve(const char *path, char *const argv[],
                              char *const envp[]) {
  if (path == nullptr || argv == nullptr || envp == nullptr ||
      std::strcmp(path, "/system/bin/dumpsys") != 0 || argv[0] == nullptr ||
      argv[1] == nullptr || argv[2] != nullptr ||
      std::strcmp(argv[0], "/system/bin/dumpsys") != 0 ||
      std::strcmp(argv[1], "display") != 0)
    child_exit(90);
  const int stdout_flags = fcntl(STDOUT_FILENO, F_GETFL);
  const int stderr_flags = fcntl(STDERR_FILENO, F_GETFL);
  if (stdout_flags < 0 || stderr_flags < 0 ||
      (stdout_flags & O_NONBLOCK) != 0 ||
      (stderr_flags & O_NONBLOCK) != 0)
    child_exit(91);
  if (wrapper_mode == 2) {
    const std::string identity = std::to_string(getpid()) + "\n";
    if (write(STDOUT_FILENO, identity.data(), identity.size()) !=
        static_cast<ssize_t>(identity.size()))
      child_exit(93);
    for (;;) pause();
  }
  std::array<char, 4096> block{};
  for (std::size_t index = 0U; index != block.size(); ++index)
    block[index] = static_cast<char>('A' + (index % 23U));
  std::size_t written = 0U;
  while (written != kLargeOutputBytes) {
    const std::size_t take =
        std::min(block.size(), kLargeOutputBytes - written);
    const ssize_t count = write(STDOUT_FILENO, block.data(), take);
    if (count > 0) {
      written += static_cast<std::size_t>(count);
    } else if (count < 0 && errno == EINTR) {
      continue;
    } else {
      child_exit(92);
    }
  }
  child_exit(0);
}

int main() {
  int checks = 0;
  auto require = [&](bool condition, const char *message) {
    ++checks;
    if (!condition) {
      std::cerr << "FAIL: " << message << '\n';
      std::exit(1);
    }
  };

  std::int64_t now = 0;
  require(monotonic_ns(&now), "monotonic clock is available");
  wrapper_mode = 1;
  CommandResult large;
  require(run_command(nppcap::FrozenCommand::kDisplay,
                      kLargeOutputBytes, now + 5LL * 1000LL * 1000LL * 1000LL,
                      &large),
          "blocking child writes and concurrent parent drain succeed");
  require(large.stdout_bytes.size() == kLargeOutputBytes,
          "large output is complete");
  require(large.stderr_bytes.empty() && large.exit_code == 0,
          "large output command terminates cleanly");
  for (std::size_t index = 0U; index != large.stdout_bytes.size(); ++index)
    if (large.stdout_bytes[index] != static_cast<char>('A' + (index % 4096U) % 23U))
      require(false, "large output contents are exact");

  require(monotonic_ns(&now), "deadline clock is available");
  wrapper_mode = 2;
  const auto timeout_started = std::chrono::steady_clock::now();
  CommandResult timed_out;
  require(!run_command(nppcap::FrozenCommand::kDisplay, 4096U,
                       now + 100LL * 1000LL * 1000LL, &timed_out),
          "hung child is killed and reaped at the deadline");
  const auto elapsed = std::chrono::steady_clock::now() - timeout_started;
  require(elapsed < std::chrono::seconds(2),
          "kill/reap path returns within its host hard allowance");
  char *pid_end = nullptr;
  errno = 0;
  const long observed_pid =
      std::strtol(timed_out.stdout_bytes.c_str(), &pid_end, 10);
  require(errno == 0 && observed_pid > 0 && pid_end != nullptr &&
              *pid_end == '\n' && pid_end[1] == '\0',
          "hung child reports its exact process identity before blocking");
  int stale_status = 0;
  errno = 0;
  require(waitpid(static_cast<pid_t>(observed_pid), &stale_status, WNOHANG) ==
                  -1 &&
              errno == ECHILD,
          "runner has already reaped the exact killed child");
  errno = 0;
  require(kill(static_cast<pid_t>(observed_pid), 0) == -1 && errno == ESRCH,
          "exact killed child no longer exists");

  require(!run_command(static_cast<nppcap::FrozenCommand>(255U), 4096U,
                       now + 1000LL * 1000LL * 1000LL, &timed_out),
          "mutated command authority rejects before fork");
  std::cout << "PASS command_runner_posix_test checks=" << checks << '\n';
  return 0;
}
