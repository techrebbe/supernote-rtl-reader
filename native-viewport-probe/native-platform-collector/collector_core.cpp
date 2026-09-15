#include "collector_core.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <utility>

namespace nppcap {
namespace {

extern const char kActivityHeader[];
extern const char kWindowHeader[];
extern const char kDisplayHeader[];
extern const char kProcessHeader[];
extern const char kProcessAuthority[];

bool fail(std::string *error, const std::string &message);
std::string trim(const std::string &line);
bool split_lines(const std::string &raw, std::size_t maximum,
                 const std::string &label, std::vector<std::string> *lines,
                 std::string *error);
bool decimal(const std::string &text, std::uint64_t maximum,
             std::uint64_t *value);
bool boolean_text(const std::string &value);
bool relevant_package(const std::string &value);
bool token_syntax(const std::string &value);
bool serial_syntax(const std::string &value);
bool uuid_syntax(const std::string &value);
bool component_syntax(const std::string &value, std::string *package);
struct OwnedMatch {
  std::vector<std::string> groups;
  const std::string &operator[](std::size_t index) const { return groups.at(index); }
};
bool find_unique_prefix(const std::vector<std::string> &lines,
                        std::size_t begin, std::size_t end,
                        const std::string &prefix, std::string *value);
bool find_unique_regex(const std::vector<std::string> &lines,
                       std::size_t begin, std::size_t end,
                       const std::regex &pattern, OwnedMatch *result);
const ProcessFact *process_for(const std::vector<ProcessFact> &processes,
                               std::uint32_t pid);

struct ActivityItem {
  std::uint32_t display{};
  std::uint32_t stack{};
  std::uint32_t task{};
  std::uint32_t pid{};
  std::uint32_t uid{};
  std::string package;
  std::string component;
  std::string task_token;
  std::string activity_token;
  std::string resumed;
  std::array<std::string, 11> body;
};

struct ActivityResult {
  std::string payload;
  std::vector<std::uint32_t> displays;
  std::vector<ActivityItem> items;
};

bool find_unique_token(const std::vector<std::string> &lines,
                       std::size_t begin, std::size_t end,
                       const std::string &key, std::string *value) {
  bool found = false;
  for (std::size_t index = begin; index != end; ++index) {
    const std::string item = trim(lines[index]);
    std::size_t cursor = 0U;
    while (cursor < item.size()) {
      while (cursor < item.size() && item[cursor] == ' ') ++cursor;
      const std::size_t token_end = item.find(' ', cursor);
      const std::size_t finish = token_end == std::string::npos
                                     ? item.size() : token_end;
      if (finish > cursor && item.compare(cursor, key.size(), key) == 0) {
        if (found || finish == cursor + key.size()) return false;
        *value = item.substr(cursor + key.size(), finish - cursor - key.size());
        found = true;
      }
      if (token_end == std::string::npos) break;
      cursor = token_end + 1U;
    }
  }
  return found;
}

bool block_mentions_scope(const std::vector<std::string> &lines,
                          std::size_t begin, std::size_t end) {
  for (std::size_t index = begin; index != end; ++index) {
    if (lines[index].find(kForeignPackage) != std::string::npos ||
        lines[index].find(kHostPackage) != std::string::npos)
      return true;
  }
  return false;
}

bool normalize_activity(const std::string &raw,
                        const std::vector<ProcessFact> &processes,
                        ActivityResult *result, std::string *error) {
  std::vector<std::string> lines;
  if (!split_lines(raw, kMaxActivityBytes, "ActivityManager", &lines, error))
    return false;
  if (lines.empty() || lines.front() != kActivityHeader)
    return fail(error, "ActivityManager source header differs");

  static const std::regex display_pattern(
      R"(^Display #([0-9]+) \(activities from top to bottom\):$)");
  static const std::regex stack_pattern(
      R"(^Stack #([0-9]+): type=standard mode=fullscreen$)");
  static const std::regex task_pattern(
      R"(^\* Task\{([0-9a-f]{1,64}) #([0-9]+) visible=(true|false) type=([a-z_]+) mode=([a-z_]+) translucent=(true|false) A=([0-9]+):([^ ]+) U=0 StackId=([0-9]+) sz=1\}$)");
  static const std::regex detail_pattern(
      R"(^taskId=([0-9]+) stackId=([0-9]+)$)");
  static const std::regex history_pattern(
      R"(^\* Hist #0: ActivityRecord\{([0-9a-f]{1,64}) u0 ([^ ]+) t([0-9]+)\}$)");
  static const std::regex package_pattern(
      R"(^packageName=([^ ]+) processName=([^ ]+)$)");
  static const std::regex app_pattern(
      R"(^app=ProcessRecord\{[0-9a-f]{1,64} ([0-9]+):([^/ ]+)/([0-9]+)\}$)");
  static const std::regex lifecycle_pattern(
      R"(^state=([A-Z_]+) stopped=(true|false) delayedResume=(true|false) finishing=(true|false)(?: .*)?$)");
  static const std::regex resumed_pattern(
      R"(^mResumedActivity: (null|ActivityRecord\{([0-9a-f]{1,64}) u0 ([^ ]+) t([0-9]+)\})$)");
  static const std::regex foreign_config_pattern(
      R"(^\{1\.0 en_US 300dpi port winConfig=\{ mBounds=Rect\([0-9]+, [0-9]+ - [0-9]+, [0-9]+\) mAppBounds=Rect\([0-9]+, [0-9]+ - [0-9]+, [0-9]+\) mRotation=ROTATION_[0-3]\} s\.(0|[1-9][0-9]*)\}$)");

  result->displays.clear();
  result->items.clear();
  std::uint64_t current_display = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t current_stack = std::numeric_limits<std::uint64_t>::max();
  std::size_t stack_begin = 0U;
  std::size_t stack_end = 0U;
  for (std::size_t index = 1U; index != lines.size(); ++index) {
    const std::string item = trim(lines[index]);
    std::smatch match;
    if (std::regex_match(item, match, display_pattern)) {
      if (!decimal(match[1].str(), 1024U, &current_display))
        return fail(error, "ActivityManager display ID is invalid");
      result->displays.push_back(static_cast<std::uint32_t>(current_display));
      current_stack = std::numeric_limits<std::uint64_t>::max();
      continue;
    }
    if (std::regex_match(item, match, stack_pattern)) {
      if (!decimal(match[1].str(), 10000000U, &current_stack))
        return fail(error, "ActivityManager stack ID is invalid");
      stack_begin = index + 1U;
      stack_end = lines.size();
      for (std::size_t probe = stack_begin; probe != lines.size(); ++probe) {
        const std::string candidate = trim(lines[probe]);
        std::smatch ignored;
        if (std::regex_match(candidate, ignored, stack_pattern) ||
            std::regex_match(candidate, ignored, display_pattern)) {
          stack_end = probe;
          break;
        }
      }
      continue;
    }

    const bool taskish = item.rfind("* Task{", 0U) == 0U;
    if (!taskish) continue;
    std::size_t block_end = lines.size();
    for (std::size_t probe = index + 1U; probe != lines.size(); ++probe) {
      const std::string candidate = trim(lines[probe]);
      std::smatch ignored;
      if (candidate.rfind("* Task{", 0U) == 0U ||
          std::regex_match(candidate, ignored, stack_pattern) ||
          std::regex_match(candidate, ignored, display_pattern)) {
        block_end = probe;
        break;
      }
    }
    const bool mentions_scope = block_mentions_scope(lines, index, block_end);
    if (!std::regex_match(item, match, task_pattern)) {
      if (mentions_scope)
        return fail(error, "relevant ActivityManager task header is malformed");
      index = block_end - 1U;
      continue;
    }
    const std::string package = match[8].str();
    if (!relevant_package(package)) {
      if (mentions_scope)
        return fail(error, "relevant ActivityManager evidence is hidden in an unrelated task");
      index = block_end - 1U;
      continue;
    }
    if (!mentions_scope)
      return fail(error, "relevant ActivityManager task lost scoped evidence");
    if (current_display == std::numeric_limits<std::uint64_t>::max() ||
        current_stack == std::numeric_limits<std::uint64_t>::max() ||
        index < stack_begin || index >= stack_end)
      return fail(error, "relevant ActivityManager task lacks display/stack scope");
    if (block_end > stack_end) block_end = stack_end;
    std::uint64_t task_id = 0U, affinity_uid = 0U, header_stack = 0U;
    if (!decimal(match[2].str(), 10000000U, &task_id) || task_id == 0U ||
        !decimal(match[7].str(), 2147483647U, &affinity_uid) ||
        !decimal(match[9].str(), 10000000U, &header_stack) ||
        match[4].str() != "standard" || match[5].str() != "fullscreen" ||
        match[6].str() != "false" || task_id != current_stack ||
        header_stack != current_stack)
      return fail(error, "relevant ActivityManager task authority differs");

    OwnedMatch detail, history, package_line, app, lifecycle;
    if (!find_unique_regex(lines, index + 1U, block_end, detail_pattern, &detail) ||
        !find_unique_regex(lines, index + 1U, block_end, history_pattern, &history) ||
        !find_unique_regex(lines, index + 1U, block_end, package_pattern, &package_line) ||
        !find_unique_regex(lines, index + 1U, block_end, app_pattern, &app) ||
        !find_unique_regex(lines, index + 1U, block_end, lifecycle_pattern, &lifecycle))
      return fail(error, "relevant ActivityManager task fields are missing or ambiguous");

    std::string activity_component, base_dir, configuration, now_line;
    if (!find_unique_prefix(lines, index + 1U, block_end,
                            "mActivityComponent=", &activity_component) ||
        !find_unique_prefix(lines, index + 1U, block_end, "baseDir=", &base_dir) ||
        !find_unique_prefix(lines, index + 1U, block_end,
                            "CurrentConfiguration=", &configuration) ||
        !find_unique_prefix(lines, index + 1U, block_end, "nowVisible=", &now_line))
      return fail(error, "relevant ActivityManager detail is missing or ambiguous");

    std::array<std::string, 5> visibility{};
    const std::array<std::string, 5> visibility_keys = {
        "mVisibleRequested=", "mVisible=", "mClientVisible=",
        "reportedDrawn=", "reportedVisible="};
    for (std::size_t field = 0U; field != visibility.size(); ++field) {
      if (!find_unique_token(lines, index + 1U, block_end,
                             visibility_keys[field], &visibility[field]) ||
          !boolean_text(visibility[field]))
        return fail(error, "ActivityManager visibility field is missing or ambiguous");
    }
    const std::size_t now_space = now_line.find(' ');
    const std::string now_value = now_line.substr(0U, now_space);
    if (!boolean_text(now_value) || now_space == std::string::npos ||
        now_space + 1U == now_line.size())
      return fail(error, "ActivityManager now-visible field is malformed");

    std::uint64_t detail_task = 0U, detail_stack = 0U, history_task = 0U;
    std::uint64_t pid = 0U, app_uid = 0U;
    if (!decimal(detail[1], 10000000U, &detail_task) ||
        !decimal(detail[2], 10000000U, &detail_stack) ||
        !decimal(history[3], 10000000U, &history_task) ||
        !decimal(app[1], kMaxPid, &pid) || pid == 0U ||
        !decimal(app[3], 2147483647U, &app_uid) ||
        detail_task != task_id || detail_stack != task_id ||
        history_task != task_id || package_line[1] != package ||
        package_line[2] != package || app[2] != package ||
        app_uid != affinity_uid)
      return fail(error, "ActivityManager task/process fields disagree");
    std::string component_package;
    if (!component_syntax(history[2], &component_package) ||
        !component_syntax(activity_component, &component_package) ||
        component_package != package || history[2] != activity_component ||
        !token_syntax(match[1].str()) || !token_syntax(history[1]) ||
        base_dir.empty() || base_dir.front() != '/' ||
        base_dir.size() > 4096U || base_dir.rfind(".apk") != base_dir.size() - 4U)
      return fail(error, "ActivityManager component/APK evidence differs");
    const ProcessFact *process = process_for(
        processes, static_cast<std::uint32_t>(pid));
    if (process == nullptr || process->uid != app_uid ||
        process->package != package)
      return fail(error, "ActivityManager process is absent from process facts");
    if (package == kForeignPackage &&
        !std::regex_match(configuration, foreign_config_pattern))
      return fail(error, "foreign ActivityManager configuration dialect differs");

    OwnedMatch resumed;
    if (!find_unique_regex(lines, stack_begin, stack_end,
                           resumed_pattern, &resumed))
      return fail(error, "ActivityManager resumed marker is missing or ambiguous");
    const std::string resumed_text = resumed[1];

    ActivityItem output;
    output.display = static_cast<std::uint32_t>(current_display);
    output.stack = static_cast<std::uint32_t>(current_stack);
    output.task = static_cast<std::uint32_t>(task_id);
    output.pid = static_cast<std::uint32_t>(pid);
    output.uid = static_cast<std::uint32_t>(app_uid);
    output.package = package;
    output.component = activity_component;
    output.task_token = match[1].str();
    output.activity_token = history[1];
    output.resumed = resumed_text;
    output.body = {
        "    " + item,
        "      taskId=" + std::to_string(task_id) + " stackId=" +
            std::to_string(task_id),
        "      * Hist #0: ActivityRecord{" + output.activity_token +
            " u0 " + output.component + " t" + std::to_string(task_id) + "}",
        "          packageName=" + package + " processName=" + package,
        "          app=ProcessRecord{" + std::string("0") + " " +
            std::to_string(pid) + ":" + package + "/" +
            std::to_string(app_uid) + "}",
        "          mActivityComponent=" + output.component,
        "          baseDir=" + base_dir,
        "          CurrentConfiguration=" + configuration,
        "          state=" + lifecycle[1] + " stopped=" +
            lifecycle[2] + " delayedResume=" + lifecycle[3] +
            " finishing=" + lifecycle[4],
        "          mVisibleRequested=" + visibility[0] + " mVisible=" +
            visibility[1] + " mClientVisible=" + visibility[2] +
            " reportedDrawn=" + visibility[3] + " reportedVisible=" +
            visibility[4],
        "          nowVisible=" + now_line};
    result->items.push_back(std::move(output));
    index = block_end - 1U;
  }

  if (result->displays.empty() || result->displays.size() > kMaxRows ||
      result->items.size() > kMaxRows)
    return fail(error, "ActivityManager inventory cardinality differs");
  std::sort(result->displays.begin(), result->displays.end());
  if (std::adjacent_find(result->displays.begin(), result->displays.end()) !=
      result->displays.end())
    return fail(error, "ActivityManager display identity is duplicated");
  std::sort(result->items.begin(), result->items.end(),
            [](const ActivityItem &left, const ActivityItem &right) {
              return std::tie(left.display, left.stack, left.task) <
                     std::tie(right.display, right.stack, right.task);
            });
  std::set<std::uint32_t> task_ids;
  std::set<std::string> activity_tokens, task_tokens, packages;
  std::set<std::pair<std::uint32_t, std::uint32_t>> stacks;
  for (const ActivityItem &item : result->items) {
    if (!task_ids.insert(item.task).second ||
        !activity_tokens.insert(item.activity_token).second ||
        !task_tokens.insert(item.task_token).second ||
        !packages.insert(item.package).second ||
        !stacks.insert({item.display, item.stack}).second)
      return fail(error, "ActivityManager relevant identity is ambiguous");
  }
  std::ostringstream normalized;
  normalized << kActivityHeader << '\n' << "Display areas in focus order:\n";
  for (std::uint32_t display : result->displays) {
    normalized << "Display #" << display
               << " (activities from top to bottom):\n";
    for (const ActivityItem &item : result->items) {
      if (item.display != display) continue;
      normalized << "  Stack #" << item.stack
                 << ": type=standard mode=fullscreen\n";
      normalized << "    mResumedActivity: " << item.resumed << '\n';
      for (const std::string &line : item.body) normalized << line << '\n';
    }
  }
  result->payload = normalized.str();
  if (result->payload.size() > kMaxActivityBytes)
    return fail(error, "normalized ActivityManager payload is oversized");
  return true;
}

bool find_unique_search(const std::vector<std::string> &lines,
                        std::size_t begin, std::size_t end,
                        const std::regex &pattern, OwnedMatch *result) {
  bool found = false;
  for (std::size_t index = begin; index != end; ++index) {
    std::smatch current;
    const std::string item = trim(lines[index]);
    if (!std::regex_search(item, current, pattern)) continue;
    if (found) return false;
    result->groups.clear();
    for (const auto &group : current) result->groups.push_back(group.str());
    found = true;
  }
  return found;
}

bool rect_syntax(const std::string &value) {
  static const std::regex pattern(
      R"(^\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]$)");
  std::smatch match;
  if (!std::regex_match(value, match, pattern)) return false;
  std::uint64_t left = 0U, top = 0U, right = 0U, bottom = 0U;
  return decimal(match[1].str(), 32768U, &left) &&
         decimal(match[2].str(), 32768U, &top) &&
         decimal(match[3].str(), 32768U, &right) &&
         decimal(match[4].str(), 32768U, &bottom) &&
         right > left && bottom > top;
}

struct WindowItem {
  std::string handle;
  const ActivityItem *activity{};
  std::uint32_t pid{};
  std::uint32_t uid{};
  std::string frame;
  std::string surface_frame;
  std::string buffer;
  bool visible{};
  bool focused{};
};

bool normalize_window(const std::string &raw,
                      const std::vector<ProcessFact> &processes,
                      const ActivityResult &activity,
                      std::string *payload, std::string *error) {
  std::vector<std::string> lines;
  if (!split_lines(raw, kMaxWindowBytes, "WindowManager", &lines, error))
    return false;
  if (lines.empty() || lines.front() != kWindowHeader)
    return fail(error, "WindowManager source header differs");
  static const std::regex window_pattern(
      R"(^Window #([0-9]+) Window\{([0-9a-f]{1,64}) u0 ([^ ]+)\}:$)");
  static const std::regex session_pattern(
      R"(mSession=Session\{[0-9a-f]{1,64} ([0-9]+):([0-9]+)\})");
  static const std::regex owner_pattern(
      R"(^mOwnerUid=([0-9]+) package=([^ ]+)(?: .*)?$)");
  static const std::regex display_pattern(
      R"(^mDisplayId=([0-9]+)(?: .*)?$)");
  static const std::regex activity_pattern(
      R"(ActivityRecord\{([0-9a-f]{1,64}) u0 ([^ ]+) t([0-9]+)\})");
  static const std::regex focus_pattern(
      R"(mCurrentFocus=Window\{([0-9a-f]{1,64}) u0 ([^ }]+)\})");
  static const std::regex buffer_pattern(R"(^([0-9]+)x([0-9]+)$)");

  std::vector<WindowItem> windows;
  for (std::size_t index = 1U; index != lines.size(); ++index) {
    const std::string item = trim(lines[index]);
    if (item.rfind("Window #", 0U) != 0U) continue;
    std::size_t block_end = lines.size();
    for (std::size_t probe = index + 1U; probe != lines.size(); ++probe) {
      const std::string candidate = trim(lines[probe]);
      if (candidate.rfind("Window #", 0U) == 0U) {
        block_end = probe;
        break;
      }
    }
    const bool mentions_scope = block_mentions_scope(lines, index, block_end);
    std::smatch header;
    if (!std::regex_match(item, header, window_pattern)) {
      if (mentions_scope)
        return fail(error, "relevant WindowManager header is malformed");
      index = block_end - 1U;
      continue;
    }
    std::string component_package;
    if (!component_syntax(header[3].str(), &component_package)) {
      if (mentions_scope)
        return fail(error, "relevant WindowManager component is malformed");
      index = block_end - 1U;
      continue;
    }
    if (!relevant_package(component_package)) {
      if (mentions_scope)
        return fail(error, "relevant WindowManager evidence is hidden in an unrelated window");
      index = block_end - 1U;
      continue;
    }
    if (!mentions_scope)
      return fail(error, "relevant WindowManager window lost scoped evidence");

    OwnedMatch session, owner, display, activity_record;
    if (!find_unique_search(lines, index + 1U, block_end,
                            session_pattern, &session) ||
        !find_unique_regex(lines, index + 1U, block_end,
                           owner_pattern, &owner) ||
        !find_unique_regex(lines, index + 1U, block_end,
                           display_pattern, &display) ||
        !find_unique_search(lines, index + 1U, block_end,
                            activity_pattern, &activity_record))
      return fail(error, "relevant WindowManager identity is missing or ambiguous");
    std::string frame, surface, buffer, visible_text;
    if (!find_unique_prefix(lines, index + 1U, block_end,
                            "mFrame=", &frame) ||
        !find_unique_prefix(lines, index + 1U, block_end,
                            "mSurfaceFrame=", &surface) ||
        !find_unique_prefix(lines, index + 1U, block_end,
                            "mBufferSize=", &buffer) ||
        !find_unique_prefix(lines, index + 1U, block_end,
                            "isVisible=", &visible_text) ||
        !rect_syntax(frame) || !rect_syntax(surface) ||
        !boolean_text(visible_text))
      return fail(error, "relevant WindowManager geometry/state is missing or ambiguous");
    std::smatch buffer_match;
    std::uint64_t width = 0U, height = 0U;
    if (!std::regex_match(buffer, buffer_match, buffer_pattern) ||
        !decimal(buffer_match[1].str(), 32768U, &width) || width == 0U ||
        !decimal(buffer_match[2].str(), 32768U, &height) || height == 0U)
      return fail(error, "WindowManager buffer size is malformed");

    std::uint64_t pid = 0U, session_uid = 0U, owner_uid = 0U;
    std::uint64_t display_id = 0U, task_id = 0U;
    if (!decimal(session[1], kMaxPid, &pid) || pid == 0U ||
        !decimal(session[2], 2147483647U, &session_uid) ||
        !decimal(owner[1], 2147483647U, &owner_uid) ||
        !decimal(display[1], 1024U, &display_id) ||
        !decimal(activity_record[3], 10000000U, &task_id) ||
        task_id == 0U || session_uid != owner_uid ||
        owner[2] != component_package ||
        activity_record[2] != header[3].str())
      return fail(error, "WindowManager owner/display/activity fields disagree");
    const ProcessFact *process = process_for(processes,
        static_cast<std::uint32_t>(pid));
    if (process == nullptr || process->uid != owner_uid ||
        process->package != component_package)
      return fail(error, "WindowManager owner is absent from process facts");
    const auto selected = std::find_if(
        activity.items.begin(), activity.items.end(),
        [&](const ActivityItem &candidate) {
          return candidate.display == display_id && candidate.task == task_id &&
                 candidate.activity_token == activity_record[1] &&
                 candidate.component == header[3].str() &&
                 candidate.pid == pid && candidate.uid == owner_uid;
        });
    if (selected == activity.items.end())
      return fail(error, "WindowManager record has no exact ActivityManager peer");

    WindowItem output;
    output.handle = header[2].str();
    output.activity = &*selected;
    output.pid = static_cast<std::uint32_t>(pid);
    output.uid = static_cast<std::uint32_t>(owner_uid);
    output.frame = frame;
    output.surface_frame = surface;
    output.buffer = buffer;
    output.visible = visible_text == "true";
    windows.push_back(std::move(output));
    index = block_end - 1U;
  }
  if (windows.size() != activity.items.size() || windows.size() > kMaxRows)
    return fail(error, "WindowManager/ActivityManager relevant cardinality differs");

  std::set<std::string> focused_handles;
  for (const std::string &line : lines) {
    std::smatch focus;
    const std::string item = trim(line);
    if (!std::regex_search(item, focus, focus_pattern)) continue;
    std::string package;
    if (!component_syntax(focus[2].str(), &package) ||
        !relevant_package(package)) continue;
    if (!focused_handles.insert(focus[1].str()).second)
      return fail(error, "WindowManager relevant focus is duplicated");
  }
  for (WindowItem &window : windows)
    window.focused = focused_handles.count(window.handle) == 1U;
  for (const std::string &handle : focused_handles) {
    if (std::none_of(windows.begin(), windows.end(),
                     [&](const WindowItem &item) {
                       return item.handle == handle;
                     }))
      return fail(error, "WindowManager focus names an absent relevant window");
  }
  std::sort(windows.begin(), windows.end(),
            [](const WindowItem &left, const WindowItem &right) {
              return std::tie(left.activity->display, left.activity->task,
                              left.activity->activity_token) <
                     std::tie(right.activity->display, right.activity->task,
                              right.activity->activity_token);
            });
  std::set<std::string> handles;
  for (const WindowItem &window : windows) {
    if (!handles.insert(window.handle).second)
      return fail(error, "WindowManager relevant handle is duplicated");
  }

  std::ostringstream normalized;
  normalized << kWindowHeader << '\n';
  std::vector<std::pair<std::uint32_t, std::string>> focuses;
  for (const WindowItem &window : windows) {
    if (window.focused)
      focuses.push_back({window.activity->display,
                         window.activity->activity_token});
  }
  std::sort(focuses.begin(), focuses.end());
  if (std::adjacent_find(focuses.begin(), focuses.end()) != focuses.end())
    return fail(error, "WindowManager normalized focus is ambiguous");
  for (const auto &focus : focuses)
    normalized << "FocusedWindow displayId=" << focus.first
               << " activityToken=" << focus.second << '\n';
  for (std::size_t ordinal = 0U; ordinal != windows.size(); ++ordinal) {
    const WindowItem &window = windows[ordinal];
    const ActivityItem &peer = *window.activity;
    normalized << "Window #" << ordinal << " Window{" << window.handle
               << " u0 " << peer.component << "}:\n"
               << "  owner pid=" << window.pid << " uid=" << window.uid
               << " package=" << peer.package << '\n'
               << "  taskId=" << peer.task << " activityToken="
               << peer.activity_token << " displayId=" << peer.display << '\n'
               << "  frame=" << window.frame << " surfaceFrame="
               << window.surface_frame << " buffer=" << window.buffer << '\n'
               << "  visible=" << (window.visible ? "true" : "false")
               << " focused=" << (window.focused ? "true" : "false") << '\n';
  }
  normalized << "END windowCount=" << windows.size()
             << " focusedCount=" << focuses.size() << '\n';
  *payload = normalized.str();
  if (payload->size() > kMaxWindowBytes)
    return fail(error, "normalized WindowManager payload is oversized");
  return true;
}

bool safe_name_token(const std::string &value) {
  if (value.empty() || value.size() > 256U) return false;
  return std::all_of(value.begin(), value.end(), [](char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' ||
           c == ':' || c == '/' || c == '@' || c == '+' || c == '-';
  });
}

struct DisplayItem {
  std::uint32_t id{};
  std::string unique_id;
  std::string name;
  const ProcessFact *owner{};
  std::uint32_t width{};
  std::uint32_t height{};
  std::uint32_t density{};
  std::vector<std::string> flags;
};

bool normalize_display(const std::string &raw,
                       const std::vector<ProcessFact> &processes,
                       const ActivityResult &activity,
                       std::string *payload, std::string *error) {
  std::vector<std::string> lines;
  if (!split_lines(raw, kMaxDisplayBytes, "DisplayManager", &lines, error))
    return false;
  if (lines.empty() || lines.front() != "DISPLAY MANAGER (dumpsys display)")
    return fail(error, "DisplayManager source header differs");
  static const std::regex block_pattern(R"(^Display ([0-9]+):$)");
  static const std::regex inventory_pattern(
      R"(^Logical Displays: size=([0-9]+)$)");
  static const std::regex name_pattern(
      R"rx(mBaseDisplayInfo=DisplayInfo\{"([^"]{1,256})")rx");
  static const std::regex id_pattern(R"(displayId ([0-9]+))");
  static const std::regex metrics_pattern(
      R"(real ([0-9]+) x ([0-9]+))");
  static const std::regex density_pattern(R"(density ([0-9]+)(?:[ ,)]|$))");
  static const std::regex state_pattern(R"(state ([A-Z_]+)(?:[ ,}]|$))");
  static const std::regex unique_pattern(
      R"rx(uniqueId "([^"]{1,4096})")rx");
  static const std::regex owner_pattern(
      R"(owner ([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+) \(uid ([0-9]+)\))");
  std::size_t inventory_start = 0U;
  std::uint64_t declared_count = 0U;
  bool inventory_found = false;
  for (std::size_t index = 1U; index != lines.size(); ++index) {
    std::smatch inventory;
    const std::string item = trim(lines[index]);
    if (!std::regex_match(item, inventory, inventory_pattern)) continue;
    if (inventory_found || !decimal(inventory[1].str(), kMaxRows,
                                    &declared_count) || declared_count == 0U)
      return fail(error, "DisplayManager logical inventory header is ambiguous");
    inventory_found = true;
    inventory_start = index + 1U;
  }
  if (!inventory_found)
    return fail(error, "DisplayManager logical inventory header is absent");
  std::vector<DisplayItem> displays;
  for (std::size_t index = inventory_start; index != lines.size(); ++index) {
    std::smatch header;
    const std::string item = trim(lines[index]);
    if (!std::regex_match(item, header, block_pattern)) continue;
    std::size_t block_end = lines.size();
    for (std::size_t probe = index + 1U; probe != lines.size(); ++probe) {
      std::smatch ignored;
      const std::string candidate = trim(lines[probe]);
      if (std::regex_match(candidate, ignored, block_pattern)) {
        block_end = probe;
        break;
      }
    }
    OwnedMatch base;
    if (!find_unique_search(lines, index + 1U, block_end,
                            name_pattern, &base))
      return fail(error, "DisplayManager logical display lacks base authority");
    std::string base_line;
    if (!find_unique_prefix(lines, index + 1U, block_end,
                            "mBaseDisplayInfo=", &base_line))
      return fail(error, "DisplayManager base display info is ambiguous");
    const std::string searchable = "mBaseDisplayInfo=" + base_line;
    std::smatch id, metrics, density, state, unique, owner;
    if (!std::regex_search(searchable, id, id_pattern) ||
        !std::regex_search(searchable, metrics, metrics_pattern) ||
        !std::regex_search(searchable, density, density_pattern) ||
        !std::regex_search(searchable, state, state_pattern) ||
        !std::regex_search(searchable, unique, unique_pattern))
      return fail(error, "DisplayManager logical display fields are incomplete");
    std::uint64_t header_id = 0U, embedded_id = 0U, width = 0U, height = 0U;
    std::uint64_t dpi = 0U;
    if (!decimal(header[1].str(), 1024U, &header_id) ||
        !decimal(id[1].str(), 1024U, &embedded_id) ||
        !decimal(metrics[1].str(), 32768U, &width) || width == 0U ||
        !decimal(metrics[2].str(), 32768U, &height) || height == 0U ||
        !decimal(density[1].str(), 1280U, &dpi) || dpi < 72U ||
        header_id != embedded_id || state[1].str() != "ON")
      return fail(error, "DisplayManager logical display authority differs");

    DisplayItem output;
    output.id = static_cast<std::uint32_t>(header_id);
    output.name = base[1];
    output.width = static_cast<std::uint32_t>(width);
    output.height = static_cast<std::uint32_t>(height);
    output.density = static_cast<std::uint32_t>(dpi);
    const std::string raw_unique = unique[1].str();
    output.unique_id = safe_name_token(raw_unique)
                           ? raw_unique : "sha256:" + sha256_hex(raw_unique);
    const bool has_owner = std::regex_search(searchable, owner, owner_pattern);
    const bool virtual_type = searchable.find("type VIRTUAL") != std::string::npos;
    const bool built_in_type = searchable.find("type BUILT_IN") != std::string::npos;
    if (output.id == 0U) {
      if (has_owner || !built_in_type)
        return fail(error, "physical DisplayManager owner/type differs");
    } else {
      if (!has_owner || !virtual_type || !relevant_package(owner[1].str()))
        return fail(error, "virtual DisplayManager owner/type is absent");
      std::uint64_t owner_uid = 0U;
      if (!decimal(owner[2].str(), 2147483647U, &owner_uid))
        return fail(error, "DisplayManager owner UID is invalid");
      const auto selected = std::find_if(
          processes.begin(), processes.end(), [&](const ProcessFact &candidate) {
            return candidate.package == owner[1].str() &&
                   candidate.uid == owner_uid;
          });
      if (selected == processes.end() ||
          std::count_if(processes.begin(), processes.end(),
                        [&](const ProcessFact &candidate) {
                          return candidate.package == owner[1].str();
                        }) != 1)
        return fail(error, "DisplayManager owner is absent or ambiguous");
      output.owner = &*selected;
      if (searchable.find("FLAG_PRIVATE") == std::string::npos)
        output.flags.push_back("PUBLIC");
      if (searchable.find("FLAG_OWN_CONTENT_ONLY") != std::string::npos)
        output.flags.push_back("OWN_CONTENT_ONLY");
      if (searchable.find("FLAG_DESTROY_CONTENT_ON_REMOVAL") != std::string::npos)
        output.flags.push_back("DESTROY_CONTENT_ON_REMOVAL");
      std::sort(output.flags.begin(), output.flags.end());
    }
    displays.push_back(std::move(output));
    index = block_end - 1U;
  }
  if (displays.empty() || displays.size() > kMaxRows ||
      displays.size() != declared_count)
    return fail(error, "DisplayManager logical display inventory is absent");
  std::sort(displays.begin(), displays.end(),
            [](const DisplayItem &left, const DisplayItem &right) {
              return left.id < right.id;
            });
  for (std::size_t index = 1U; index != displays.size(); ++index) {
    if (displays[index - 1U].id == displays[index].id)
      return fail(error, "DisplayManager display ID is duplicated");
  }
  if (activity.displays.size() != displays.size())
    return fail(error, "ActivityManager/DisplayManager display count differs");
  for (std::size_t index = 0U; index != displays.size(); ++index) {
    if (activity.displays[index] != displays[index].id)
      return fail(error, "ActivityManager/DisplayManager display IDs differ");
  }

  std::ostringstream normalized;
  normalized << kDisplayHeader << '\n';
  for (const DisplayItem &display : displays) {
    normalized << "Display #" << display.id << ":\n"
               << "  uniqueId=" << display.unique_id << '\n'
               << "  name=" << display.name << '\n';
    if (display.owner == nullptr) {
      normalized << "  owner=none\n";
    } else {
      normalized << "  ownerPid=" << display.owner->pid
                 << " ownerUid=" << display.owner->uid
                 << " ownerPackage=" << display.owner->package << '\n';
    }
    normalized << "  metrics=" << display.width << 'x' << display.height
               << " density=" << display.density << '\n';
    if (display.flags.empty()) {
      normalized << "  flags=none\n";
    } else {
      normalized << "  flags=";
      for (std::size_t index = 0U; index != display.flags.size(); ++index) {
        if (index != 0U) normalized << ',';
        normalized << display.flags[index];
      }
      normalized << '\n';
    }
    normalized << "  state=ON\n";
  }
  normalized << "END displayCount=" << displays.size() << '\n';
  *payload = normalized.str();
  if (payload->size() > kMaxDisplayBytes)
    return fail(error, "normalized DisplayManager payload is oversized");
  return true;
}

bool validate_processes(const std::vector<ProcessFact> &processes,
                        std::string *error) {
  if (processes.empty() || processes.size() > kMaxRows)
    return fail(error, "process inventory is empty or oversized");
  if (!std::is_sorted(processes.begin(), processes.end()))
    return fail(error, "process inventory is not in PID order");
  std::set<std::uint32_t> pids;
  std::set<std::string> packages;
  for (const ProcessFact &process : processes) {
    std::uint64_t start_ticks = 0U;
    if (process.pid == 0U || process.pid > kMaxPid ||
        !decimal(process.start_ticks, 9999999999999999999ULL, &start_ticks) ||
        start_ticks == 0U || !relevant_package(process.package) ||
        !pids.insert(process.pid).second ||
        !packages.insert(process.package).second)
      return fail(error, "process inventory contains invalid or duplicate identity");
  }
  if (packages.count(kHostPackage) != 1U)
    return fail(error, "retained host process is absent");
  return true;
}

bool make_process_payload(const CaptureInputs &inputs, std::string *payload,
                          std::string *error) {
  if (!serial_syntax(inputs.serial) || !uuid_syntax(inputs.boot_id))
    return fail(error, "serial or boot ID syntax differs");
  if (inputs.installed_apk_sha256 != kPinnedInstalledApkSha256)
    return fail(error, "installed host APK digest differs");
  std::ostringstream output;
  output << kProcessHeader << '\n'
         << "authority=" << kProcessAuthority << '\n'
         << "serial=" << inputs.serial << '\n'
         << "bootId=" << inputs.boot_id << '\n'
         << "policy readOnly=true mutationCount=0 userDocumentSelectionCount=0 "
            "scopePackages=" << kForeignPackage << ',' << kHostPackage << '\n'
         << "package name=" << kHostPackage
         << " installedApkSha256=" << kPinnedInstalledApkSha256
         << " reviewedUnsignedApkSha256="
         << kPinnedReviewedUnsignedApkSha256
         << " dexSha256=" << kPinnedDexSha256
         << " signerCertSha256=" << kPinnedSignerCertSha256
         << " versionCode=" << kPinnedVersionCode
         << " versionName=" << kPinnedVersionName << '\n';
  for (const ProcessFact &process : inputs.processes)
    output << "process pid=" << process.pid
           << " startTicks=" << process.start_ticks
           << " uid=" << process.uid
           << " package=" << process.package << '\n';
  output << "END processCount=" << inputs.processes.size()
         << " packageCount=1\n";
  *payload = output.str();
  if (payload->size() > kMaxProcessBytes)
    return fail(error, "normalized process payload is oversized");
  return true;
}

}  // namespace

bool normalize_capture(const CaptureInputs &inputs, CapturePayloads *payloads,
                       std::string *error) {
  if (payloads == nullptr) return fail(error, "payload output is absent");
  if (!validate_processes(inputs.processes, error)) return false;
  ActivityResult activity;
  if (!normalize_activity(inputs.activity_raw, inputs.processes,
                          &activity, error)) return false;
  std::string window;
  if (!normalize_window(inputs.window_raw, inputs.processes,
                        activity, &window, error)) return false;
  std::string display;
  if (!normalize_display(inputs.display_raw, inputs.processes,
                         activity, &display, error)) return false;
  std::string process;
  if (!make_process_payload(inputs, &process, error)) return false;
  payloads->activity = std::move(activity.payload);
  payloads->window = std::move(window);
  payloads->process = std::move(process);
  payloads->display = std::move(display);
  return true;
}

std::vector<std::uint8_t> encode_wire(const CapturePayloads &payloads,
                                      std::string *error) {
  struct Member {
    std::uint8_t tag;
    const std::string *payload;
    std::size_t maximum;
  };
  const std::array<Member, 4> members = {{{1U, &payloads.activity,
                                           kMaxActivityBytes},
                                          {2U, &payloads.window,
                                           kMaxWindowBytes},
                                          {3U, &payloads.process,
                                           kMaxProcessBytes},
                                          {4U, &payloads.display,
                                           kMaxDisplayBytes}}};
  std::size_t total = 8U + 33U;
  for (const Member &member : members) {
    if (member.payload->empty() || member.payload->size() > member.maximum ||
        member.payload->size() > std::numeric_limits<std::uint32_t>::max()) {
      fail(error, "NPPCAP01 member is empty or oversized");
      return {};
    }
    if (total > kMaxWireBytes - 37U - member.payload->size()) {
      fail(error, "NPPCAP01 aggregate size exceeds its bound");
      return {};
    }
    total += 37U + member.payload->size();
  }
  std::vector<std::uint8_t> output;
  output.reserve(total);
  static constexpr std::array<std::uint8_t, 8> magic = {
      {'N', 'P', 'P', 'C', 'A', 'P', '0', '1'}};
  output.insert(output.end(), magic.begin(), magic.end());
  for (const Member &member : members) {
    output.push_back(member.tag);
    const std::uint32_t size =
        static_cast<std::uint32_t>(member.payload->size());
    output.push_back(static_cast<std::uint8_t>(size >> 24U));
    output.push_back(static_cast<std::uint8_t>(size >> 16U));
    output.push_back(static_cast<std::uint8_t>(size >> 8U));
    output.push_back(static_cast<std::uint8_t>(size));
    const auto digest = sha256(member.payload->data(), member.payload->size());
    output.insert(output.end(), digest.begin(), digest.end());
    output.insert(output.end(), member.payload->begin(), member.payload->end());
  }
  const auto aggregate = sha256(output.data(), output.size());
  output.push_back(0U);
  output.insert(output.end(), aggregate.begin(), aggregate.end());
  if (output.size() != total) {
    fail(error, "NPPCAP01 internal size accounting differs");
    return {};
  }
  return output;
}

}  // namespace nppcap

namespace nppcap {
namespace {

const char kActivityHeader[] =
    "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)";
const char kWindowHeader[] =
    "WINDOW MANAGER WINDOWS (dumpsys window windows)";
const char kDisplayHeader[] =
    "DISPLAY MANAGER DISPLAYS (dumpsys display)";
const char kProcessHeader[] =
    "NATIVE PAGE PROCESS FACTS (private-adb-platform-v1)";
const char kProcessAuthority[] =
    "rtl-reader-native-page-private-adb-process-facts-v1";

bool fail(std::string *error, const std::string &message) {
  if (error != nullptr) *error = message;
  return false;
}

std::uint32_t rotate_right(std::uint32_t value, unsigned count) {
  return (value >> count) | (value << (32U - count));
}

class Sha256 {
 public:
  Sha256() = default;

  void update(const std::uint8_t *data, std::size_t size) {
    if (finished_ || (data == nullptr && size != 0U)) return;
    total_ += static_cast<std::uint64_t>(size);
    while (size != 0U) {
      const std::size_t take = std::min(size, block_.size() - used_);
      std::memcpy(block_.data() + used_, data, take);
      used_ += take;
      data += take;
      size -= take;
      if (used_ == block_.size()) {
        compress(block_.data());
        used_ = 0U;
      }
    }
  }

  std::array<std::uint8_t, 32> finish() {
    if (!finished_) {
      const std::uint64_t bits = total_ * 8U;
      block_[used_++] = 0x80U;
      if (used_ > 56U) {
        std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_),
                  block_.end(), 0U);
        compress(block_.data());
        used_ = 0U;
      }
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(used_),
                block_.begin() + 56, 0U);
      for (unsigned index = 0; index != 8U; ++index) {
        block_[63U - index] = static_cast<std::uint8_t>(bits >> (index * 8U));
      }
      compress(block_.data());
      finished_ = true;
    }
    std::array<std::uint8_t, 32> result{};
    for (std::size_t index = 0; index != state_.size(); ++index) {
      for (unsigned byte = 0; byte != 4U; ++byte) {
        result[index * 4U + byte] = static_cast<std::uint8_t>(
            state_[index] >> ((3U - byte) * 8U));
      }
    }
    return result;
  }

 private:
  void compress(const std::uint8_t *input) {
    static constexpr std::array<std::uint32_t, 64> constants = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index != 16U; ++index) {
      words[index] = (static_cast<std::uint32_t>(input[index * 4U]) << 24U) |
                     (static_cast<std::uint32_t>(input[index * 4U + 1U]) << 16U) |
                     (static_cast<std::uint32_t>(input[index * 4U + 2U]) << 8U) |
                     static_cast<std::uint32_t>(input[index * 4U + 3U]);
    }
    for (std::size_t index = 16U; index != words.size(); ++index) {
      const std::uint32_t a = words[index - 15U];
      const std::uint32_t b = words[index - 2U];
      const std::uint32_t s0 = rotate_right(a, 7U) ^ rotate_right(a, 18U) ^
                               (a >> 3U);
      const std::uint32_t s1 = rotate_right(b, 17U) ^ rotate_right(b, 19U) ^
                               (b >> 10U);
      words[index] = words[index - 16U] + s0 + words[index - 7U] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (std::size_t index = 0; index != words.size(); ++index) {
      const std::uint32_t s1 = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                               rotate_right(e, 25U);
      const std::uint32_t choose = (e & f) ^ ((~e) & g);
      const std::uint32_t temp1 = h + s1 + choose + constants[index] + words[index];
      const std::uint32_t s0 = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                               rotate_right(a, 22U);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t temp2 = s0 + majority;
      h = g; g = f; f = e; e = d + temp1;
      d = c; c = b; b = a; a = temp1 + temp2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
  std::array<std::uint8_t, 64> block_{};
  std::uint64_t total_{};
  std::size_t used_{};
  bool finished_{};
};

std::string hex(const std::array<std::uint8_t, 32> &digest) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string result(64U, '0');
  for (std::size_t index = 0; index != digest.size(); ++index) {
    result[index * 2U] = alphabet[digest[index] >> 4U];
    result[index * 2U + 1U] = alphabet[digest[index] & 15U];
  }
  return result;
}

std::string trim(const std::string &line) {
  std::size_t first = 0U;
  while (first != line.size() && (line[first] == ' ' || line[first] == '\t'))
    ++first;
  std::size_t last = line.size();
  while (last != first && (line[last - 1U] == ' ' || line[last - 1U] == '\t'))
    --last;
  return line.substr(first, last - first);
}

bool split_lines(const std::string &raw, std::size_t maximum,
                 const std::string &label, std::vector<std::string> *lines,
                 std::string *error) {
  if (raw.empty() || raw.size() > maximum)
    return fail(error, label + " input is absent or oversized");
  if (raw.back() != '\n' || raw.find('\0') != std::string::npos ||
      raw.find('\r') != std::string::npos)
    return fail(error, label + " input is not canonical LF text");
  lines->clear();
  std::size_t begin = 0U;
  while (begin != raw.size()) {
    const std::size_t end = raw.find('\n', begin);
    if (end == std::string::npos || end - begin > 65536U)
      return fail(error, label + " input contains a truncated or oversized line");
    for (std::size_t index = begin; index != end; ++index) {
      const unsigned char value = static_cast<unsigned char>(raw[index]);
      if ((value < 0x20U && value != '\t') || value == 0x7fU || value > 0x7eU)
        return fail(error, label + " input is not bounded printable ASCII");
    }
    lines->push_back(raw.substr(begin, end - begin));
    if (lines->size() > 65536U)
      return fail(error, label + " input has too many lines");
    begin = end + 1U;
  }
  return true;
}

bool decimal(const std::string &text, std::uint64_t maximum,
             std::uint64_t *value) {
  if (text.empty() || (text.size() > 1U && text.front() == '0')) return false;
  std::uint64_t result = 0U;
  for (char character : text) {
    if (character < '0' || character > '9') return false;
    const unsigned digit = static_cast<unsigned>(character - '0');
    if (result > (maximum - digit) / 10U) return false;
    result = result * 10U + digit;
  }
  *value = result;
  return true;
}

bool boolean_text(const std::string &value) {
  return value == "true" || value == "false";
}

bool relevant_package(const std::string &value) {
  return value == kForeignPackage || value == kHostPackage;
}

bool token_syntax(const std::string &value) {
  return !value.empty() && value.size() <= 64U &&
         std::all_of(value.begin(), value.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

bool serial_syntax(const std::string &value) {
  if (value.empty() || value.size() > 128U || !std::isalnum(
          static_cast<unsigned char>(value.front()))) return false;
  return std::all_of(value.begin(), value.end(), [](char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '.' || c == '_' || c == '-';
  });
}

bool uuid_syntax(const std::string &value) {
  if (value.size() != 36U) return false;
  for (std::size_t index = 0; index != value.size(); ++index) {
    if (index == 8U || index == 13U || index == 18U || index == 23U) {
      if (value[index] != '-') return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return value[14] >= '1' && value[14] <= '8' &&
         (value[19] == '8' || value[19] == '9' ||
          value[19] == 'a' || value[19] == 'b');
}

bool component_syntax(const std::string &value, std::string *package) {
  static const std::regex pattern(
      R"(^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/(\.[A-Za-z0-9_.$]+|[A-Za-z][A-Za-z0-9_.$]*(?:\.[A-Za-z0-9_.$]+)*)$)");
  std::smatch match;
  if (!std::regex_match(value, match, pattern)) return false;
  *package = match[1].str();
  return true;
}

bool find_unique_prefix(const std::vector<std::string> &lines,
                        std::size_t begin, std::size_t end,
                        const std::string &prefix, std::string *value) {
  bool found = false;
  for (std::size_t index = begin; index != end; ++index) {
    const std::string item = trim(lines[index]);
    if (item.rfind(prefix, 0U) != 0U) continue;
    if (found) return false;
    *value = item.substr(prefix.size());
    found = true;
  }
  return found && !value->empty();
}

bool find_unique_regex(const std::vector<std::string> &lines,
                       std::size_t begin, std::size_t end,
                       const std::regex &pattern, OwnedMatch *result) {
  bool found = false;
  for (std::size_t index = begin; index != end; ++index) {
    std::smatch current;
    const std::string item = trim(lines[index]);
    if (!std::regex_match(item, current, pattern)) continue;
    if (found) return false;
    result->groups.clear();
    for (const auto &group : current) result->groups.push_back(group.str());
    found = true;
  }
  return found;
}

const ProcessFact *process_for(const std::vector<ProcessFact> &processes,
                               std::uint32_t pid) {
  const auto found = std::find_if(processes.begin(), processes.end(),
                                  [pid](const ProcessFact &item) {
                                    return item.pid == pid;
                                  });
  return found == processes.end() ? nullptr : &*found;
}

}  // namespace

bool ProcessFact::operator==(const ProcessFact &other) const {
  return pid == other.pid && start_ticks == other.start_ticks &&
         uid == other.uid && package == other.package;
}

bool ProcessFact::operator<(const ProcessFact &other) const {
  return pid < other.pid;
}

const FrozenCommandSpec *frozen_command_spec(FrozenCommand command) {
  static const std::array<FrozenCommandSpec, 6> commands = {{
      {2U, {{"/system/bin/getprop", "ro.serialno", nullptr, nullptr}}},
      {2U, {{"/system/bin/getprop", "ro.build.fingerprint", nullptr,
             nullptr}}},
      {4U, {{"/system/bin/cmd", "package", "path", kHostPackage}}},
      {3U, {{"/system/bin/dumpsys", "activity", "activities", nullptr}}},
      {3U, {{"/system/bin/dumpsys", "window", "windows", nullptr}}},
      {2U, {{"/system/bin/dumpsys", "display", nullptr, nullptr}}},
  }};
  const std::size_t index = static_cast<std::size_t>(command);
  return index < commands.size() ? &commands[index] : nullptr;
}

std::array<std::uint8_t, 32> sha256(const void *data, std::size_t size) {
  Sha256 context;
  context.update(static_cast<const std::uint8_t *>(data), size);
  return context.finish();
}

std::string sha256_hex(const void *data, std::size_t size) {
  return hex(sha256(data, size));
}

std::string sha256_hex(const std::string &data) {
  return sha256_hex(data.data(), data.size());
}

}  // namespace nppcap
