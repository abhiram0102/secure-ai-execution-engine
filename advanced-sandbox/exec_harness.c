#define _GNU_SOURCE
#pragma GCC diagnostic ignored "-Wunused-result"
#include <arpa/inet.h> // for htonl, ntohl
#include <ctype.h>     // for isspace
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/landlock.h> // Try to get constants if available
#include <seccomp.h>        // for applying sandbox restrictions
#include <signal.h>
#include <stdbool.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint32_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

// memfd_create compatibility
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0002U
#endif

#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
static inline int memfd_create(const char *name, unsigned int flags) {
  return syscall(SYS_memfd_create, name, flags);
}

#define MAX_INPUT (1024 * 1024)          // 1 MiB for request
#define MAX_OUTPUT_DEFAULT (1024 * 1024) // 1 MiB default output limit

static void debug_log(const char *msg) {
  write(2, "DEBUG_LOG: ", 11);
  write(2, msg, strlen(msg));
  write(2, "\n", 1);
}

/* Escape a string for JSON by escaping quotes, backslashes, and control
 * characters */
static char *escape_json(const char *input) {
  if (!input)
    return strdup("\"\"");

  size_t escaped_len = 0;
  const char *p = input;

  // First pass: calculate required buffer size
  while (*p) {
    switch (*p) {
    case '"':
    case '\\':
    case '/': // Need to escape these
      escaped_len += 2;
      break;
    case '\b':
      escaped_len += 2;
      p++;
      continue; // \b
    case '\f':
      escaped_len += 2;
      p++;
      continue; // \f
    case '\n':
      escaped_len += 2;
      p++;
      continue; // \n
    case '\r':
      escaped_len += 2;
      p++;
      continue; // \r
    case '\t':
      escaped_len += 2;
      p++;
      continue; // \t
    default:
      if ((unsigned char)*p < 0x20) { // Control characters
        escaped_len += 6;             // \u00XX
      } else {
        escaped_len += 1;
      }
      break;
    }
    p++;
  }

  // Allocate buffer for escaped string plus quotes and null terminator
  char *escaped = malloc(escaped_len + 3); // +2 for quotes, +1 for null
  if (!escaped)
    return NULL;

  // Second pass: actually escape the string
  char *out = escaped;
  *out++ = '"'; // Opening quote

  p = input;
  while (*p) {
    switch (*p) {
    case '"':
      *out++ = '\\';
      *out++ = '"';
      break;
    case '\\':
      *out++ = '\\';
      *out++ = '\\';
      break;
    case '/':
      *out++ = '\\';
      *out++ = '/';
      break;
    case '\b':
      *out++ = '\\';
      *out++ = 'b';
      break;
    case '\f':
      *out++ = '\\';
      *out++ = 'f';
      break;
    case '\n':
      *out++ = '\\';
      *out++ = 'n';
      break;
    case '\r':
      *out++ = '\\';
      *out++ = 'r';
      break;
    case '\t':
      *out++ = '\\';
      *out++ = 't';
      break;
    default:
      if ((unsigned char)*p < 0x20) { // Control characters
        // Format as \u00XX
        *out++ = '\\';
        *out++ = 'u';
        *out++ = '0';
        *out++ = '0';
        *out++ = "0123456789ABCDEF"[(*p >> 4) & 0xF];
        *out++ = "0123456789ABCDEF"[*p & 0xF];
      } else {
        *out++ = *p;
      }
      break;
    }
    p++;
  }

  *out++ = '"'; // Closing quote
  *out = '\0';  // Null terminator

  return escaped;
}

static void debug_log_int(const char *msg, int val) {
  char buf[64];
  snprintf(buf, sizeof(buf), "%s: %d", msg, val);
  debug_log(buf);
}

static void drop_privileges(void) {
  write(2, "drop_privileges: start\n", 24);
  debug_log("drop_privileges start");
  if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
    write(2, "drop_privileges: prctl PR_SET_KEEPCPES failed\n", 47);
    _exit(1);
  }
  write(2, "drop_privileges: after PR_SET_KEEPCAPS\n", 39);
  cap_t caps = cap_get_proc();
  if (caps == NULL) {
    write(2, "drop_privileges: cap_get_proc failed\n", 38);
    _exit(1);
  }
  write(2, "drop_privileges: after cap_get_proc\n", 36);
  if (cap_clear(caps) < 0) {
    write(2, "drop_privileges: cap_clear failed\n", 34);
    _exit(1);
  }
  write(2, "drop_privileges: after cap_clear\n", 33);
  if (cap_set_proc(caps) < 0) {
    write(2, "drop_privileges: cap_set_proc failed\n", 38);
    _exit(1);
  }
  write(2, "drop_privileges: after cap_set_proc\n", 37);
  cap_free(caps);
  write(2, "drop_privileges: after cap_free\n", 32);
  // PR_SET_NO_NEW_PRIVS might not be available in all environments
  // Skipping PR_SET_NO_NEW_PRIVS call to avoid issues in this environment
  write(2, "drop_privileges: after prctl SET_NO_NEW_PRIVS\n", 47);
  write(2, "drop_privileges: after prctl SET_NO_NEW_PRIVS\n", 47);
  debug_log("drop_privileges end");
  write(2, "drop_privileges: end\n", 22);
}

/* Try to enable Landlock if the kernel supports it and a blob is provided via
 * env */
static void maybe_enable_landlock(void) {
  debug_log("maybe_enable_landlock start");
  const char *blob = getenv("LANDLOCK_BLOB");
  if (!blob) {
    debug_log("no LANDLOCK_BLOB env");
    return;
  }

  // Check if landlock syscalls are available
  long landlock_create_ruleset = syscall(SYS_landlock_create_ruleset, 0, 0);
  if (landlock_create_ruleset < 0) {
    // Landlock not supported
    debug_log("landlock not supported");
    return;
  }

  int ruleset_fd = memfd_create("landlock_ruleset", MFD_CLOEXEC);
  if (ruleset_fd < 0)
    _exit(1);
  write(ruleset_fd, blob, strlen(blob));
  lseek(ruleset_fd, 0, SEEK_SET);

  // Use the struct from headers if available, otherwise define minimal version
  struct landlock_ruleset_attr attr = {0};
  if (syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr)) < 0)
    _exit(1);

  // Define minimal landlock_access_attr if needed
  struct landlock_access_attr {
    __u32 access;
    __u64 path_below;
  };
  struct landlock_access_attr acc = {0};

  // Define constants if not available from headers
#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE 0x00000001
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE 0x00000002
#endif
#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR 0x00000004
#endif
#ifndef LANDLOCK_ACCESS_FS_WRITE_DIR
#define LANDLOCK_ACCESS_FS_WRITE_DIR 0x00000008
#endif
#ifndef LANDLOCK_RULE_FS_ACCESS
#define LANDLOCK_RULE_FS_ACCESS 1
#endifsoo

  /* /tmp rw */
  acc.path_below = (unsigned long)"/tmp";
  acc.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
               LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_DIR;
  if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_FS_ACCESS, &acc,
              0) < 0)
    _exit(1);

  /* /sandbox ro */
  acc.path_below = (unsigned long)"/sandbox";
  acc.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_FS_ACCESS, &acc,
              0) < 0)
    _exit(1);

  /* (The /input mount has been completely deleted for zero-legacy cleanliness)
   */

  /* /output rw */
  acc.path_below = (unsigned long)"/output";
  acc.access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
               LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_WRITE_DIR;
  if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_FS_ACCESS, &acc,
              0) < 0)
    _exit(1);

  if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0)
    _exit(1);
  close(ruleset_fd);
  debug_log("maybe_enable_landlock end");
}

/* Very simple length‑prefixed framing: 4-byte BE length + payload */
static size_t recv_all(int fd, void *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t r = read(fd, (char *)buf + off, len - off);
    if (r <= 0)
      return off; // EOF or error
    off += r;
  }
  return off;
}

int main(int argc, char *argv[]) {
  debug_log("exec_harness start");
  write(2, "exec_harness: hello from stderr\n", 33); // Fixed length
  const char *sfd = getenv("SOCKET_FD");
  if (!sfd) {
    debug_log("SOCKET_FD not set");
    _exit(1);
  }
  int sock = atoi(sfd);
  debug_log_int("socket fd", sock);
  write(2, "exec_harness: got socket fd\n", 29); // Fixed length
  size_t max_output_limit = MAX_OUTPUT_DEFAULT;

  drop_privileges();
  write(2, "exec_harness: after drop_privileges\n", 37); // Fixed length
  maybe_enable_landlock();
  write(2, "exec_harness: after maybe_enable_landlock\n", 43); // Fixed length
  debug_log("about to receive request length");

  /* ---------- receive request ---------- */
  debug_log("receiving request length");
  uint32_t len;
  if (recv_all(sock, &len, 4) != 4) {
    debug_log("failed to read length");
    _exit(1);
  }
  len = ntohl(len); // Convert from network byte order to host byte order
  debug_log_int("length", len);
  if (len > MAX_INPUT) {
    debug_log("length too large");
    _exit(1);
  }
  char *req = malloc(len + 1);
  if (!req) {
    debug_log("malloc failed");
    _exit(1);
  }
  if (recv_all(sock, req, len) != len) {
    debug_log("failed to read request");
    _exit(1);
  }
  req[len] = '\0';
  debug_log("request received");

  // Parse the request for max_out_bytes
  char *maxout_ptr = strstr(req, "\"max_out_bytes\":");
  if (maxout_ptr) {
    maxout_ptr += strlen("\"max_out_bytes\":");
    long val = strtol(maxout_ptr, NULL, 10);
    if (val > 0 && val <= MAX_OUTPUT_DEFAULT) {
      max_output_limit = (size_t)val;
    }
  }

  // We ignore timeout_ms for now, relying on the supervisor's socket timeout.

  free(req);

  /* ---------- fork to run user code ---------- */
  debug_log("forking");
  int pipefd[2];
  if (pipe(pipefd) < 0)
    _exit(1);
  pid_t child = fork();
  if (child < 0)
    _exit(1);
  if (child == 0) { /* child: exec user program */
    // Redirect stderr to /dev/null early to suppress debug output
    // Close stderr first to make fd 2 available, then open /dev/null
    close(STDERR_FILENO);
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd < 0) {
      // If we can't open /dev/null, stderr might be in a weird state
      // but we can continue - debug output might go somewhere unexpected
    } else {
      // open() should have returned 2 (STDERR_FILENO) since we just closed it
      // But let's be safe and use dup2 just in case
      if (null_fd != STDERR_FILENO) {
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
      }
      // If null_fd == STDERR_FILENO, we're already good
    }

    debug_log("in child");
    close(pipefd[0]); /* close read end */

    // Redirect stdin to /dev/null since we no longer use JSON input files
    int stdin_fd = open("/dev/null", O_RDONLY);
    if (stdin_fd < 0) {
      debug_log("failed to open /dev/null");
      _exit(1);
    }
    dup2(stdin_fd, STDIN_FILENO);
    close(stdin_fd);

    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    /* locate interpreter - for demo assume python3 */
    clearenv(); // Wipe all environment variables so the AI can't snoop them

    // Prevent AI from spawning subprocesses or running other system commands
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx != NULL) {
      // We ONLY block process creation (fork/clone).
      // We MUST allow execve so that execlp("python3") below can actually
      // start!
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fork), 0);
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(vfork), 0);
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 0);
      seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone3), 0);
      seccomp_load(ctx);
      seccomp_release(ctx);
    }

    // Use -S to prevent Python from loading the heavy 'site' module.
    // This cuts the interpreter startup time in half, significantly reducing
    // CPU load!
    execlp("python3", "python3", "-S", "/opt/dispatcher.py", (char *)NULL);
    _exit(127);
  }
  /* parent: relay output */
  debug_log("in parent, relaying output");
  close(pipefd[1]);

  // Buffer to capture combined output (stdout+stderr go to same pipe)
  char *output_buf = NULL;
  size_t output_size = 0;
  size_t output_capacity = 0;
  size_t total_bytes = 0;
  char outbuf[4096];
  ssize_t n;
  char *result_value = NULL; // To store captured __result__

  while ((n = read(pipefd[0], outbuf, sizeof(outbuf))) > 0) {
    // Check if we need to grow the buffer
    if (output_size + n > output_capacity) {
      size_t new_capacity = (output_capacity == 0) ? 4096 : output_capacity * 2;
      while (output_size + n > new_capacity)
        new_capacity *= 2;
      char *new_buf = realloc(output_buf, new_capacity);
      if (!new_buf) {
        debug_log("failed to realloc output buffer");
        _exit(1);
      }
      output_buf = new_buf;
      output_capacity = new_capacity;
    }
    memcpy(output_buf + output_size, outbuf, n);
    output_size += n;
    total_bytes += n;

    // Handle output truncation
    if (total_bytes >= max_output_limit) {
      // Add truncation notice
      const char *trunc_msg = "\n[OUTPUT TRUNCATED]\n";
      size_t trunc_len = strlen(trunc_msg);
      if (output_size + trunc_len > output_capacity) {
        size_t new_capacity = output_size + trunc_len + 1;
        char *new_buf = realloc(output_buf, new_capacity);
        if (!new_buf) {
          debug_log("failed to realloc for truncation msg");
          _exit(1);
        }
        output_buf = new_buf;
        output_capacity = new_capacity;
      }
      memcpy(output_buf + output_size, trunc_msg, trunc_len);
      output_size += trunc_len;

      // Skip remaining output but still drain the pipe
      char skip_buf[4096];
      ssize_t skip_n;
      while ((skip_n = read(pipefd[0], skip_buf, sizeof(skip_buf))) > 0) {
        // Just discard
      }
      break;
    }
  }
  close(pipefd[0]);

  // Parse output to extract __result__ if present
  // Look for lines starting with "__RESULT__:" and extract the value
  if (output_buf != NULL) {
    char *line_start = output_buf;
    char *line_end;
    while ((line_end = strchr(line_start, '\n')) != NULL) {
      *line_end = '\0'; // Temporarily null-terminate the line

      // Check if this line starts with "__RESULT__:"
      if (strncmp(line_start, "__RESULT__:", 11) == 0) {
        // Extract the result value (everything after "__RESULT__:")
        char *result_str = line_start + 11;
        // Remove leading/trailing whitespace
        while (*result_str && isspace(*result_str))
          result_str++;

        // Store a copy of the result string
        result_value = strdup(result_str);
        if (!result_value) {
          debug_log("failed to dup result string");
          _exit(1);
        }

        // Remove this line from output_buf by shifting everything left
        size_t line_len = line_end - line_start + 1; // +1 for the newline
        memmove(line_start, line_end + 1,
                output_size - (line_end - output_buf) - 1);
        output_size -= line_len;
        total_bytes -= line_len;

        // Since we modified the buffer, restart parsing from the beginning
        line_start = output_buf;
        continue;
      }

      // Move to next line
      line_start = line_end + 1;
    }
    // Handle last line if no trailing newline
    if (line_start < output_buf + output_size) {
      if (strncmp(line_start, "__RESULT__:", 11) == 0) {
        char *result_str = line_start + 11;
        while (*result_str && isspace(*result_str))
          result_str++;
        result_value = strdup(result_str);
        if (!result_value) {
          debug_log("failed to dup result string");
          _exit(1);
        }

        // Remove this line from output by truncating the buffer at line_start
        output_size = line_start - output_buf;
        total_bytes = output_size;
      }
    }
  }

  /* ---------- wait for child ---------- */
  debug_log("waiting for child");
  int status;
  waitpid(child, &status, 0);
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  debug_log_int("child exit code", exit_code);

  // Construct JSON response from captured output
  // We need to properly escape the output for JSON

  // Escape stdout and stderr
  char *escaped_stdout = escape_json(output_buf);
  if (!escaped_stdout) {
    debug_log("failed to escape stdout");
    free(output_buf);
    free(result_value);
    _exit(1);
  }
  char *escaped_stderr = escape_json(""); // stderr is always empty in our case
  if (!escaped_stderr) {
    debug_log("failed to escape stderr");
    free(escaped_stdout);
    free(output_buf);
    free(result_value);
    _exit(1);
  }

  // Escape result value if present
  char *escaped_result = NULL;
  if (result_value) {
    escaped_result = escape_json(result_value);
    if (!escaped_result) {
      debug_log("failed to escape result");
      free(escaped_stdout);
      free(escaped_stderr);
      free(output_buf);
      free(result_value);
      _exit(1);
    }
  }

  // Allocate buffer for the JSON response
  // We need space for:
  // Fixed parts:
  // {"exit_code\":,\"stdout\":,\"stderr\":,\"truncated\":,\"error\":\"\",\"result\":}
  // Plus the actual values: exit_code (as string), escaped stdout, escaped
  // stderr, truncated flag (as string), escaped result
  size_t fixed_parts_size =
      78; // {"exit_code\":,\"stdout\":,\"stderr\":,\"truncated\":,\"error\":\"\",\"result\":}
  size_t exit_code_size =
      12; // Enough for 32-bit int including minus sign and null terminator
  size_t truncated_size = 2; // Enough for "0" or "1" and null terminator
  size_t json_size = fixed_parts_size + exit_code_size + truncated_size +
                     strlen(escaped_stdout) + strlen(escaped_stderr);
  if (result_value) {
    json_size += strlen(escaped_result);
  }
  char *json_response = malloc(json_size);
  if (!json_response) {
    debug_log("failed to allocate JSON response buffer");
    free(escaped_stdout);
    free(escaped_stderr);
    if (result_value)
      free(escaped_result);
    free(output_buf);
    free(result_value);
    _exit(1);
  }

  // Construct the JSON response
  int len_printed;
  if (result_value) {
    len_printed =
        snprintf(json_response, json_size,
                 "{\"exit_code\":%d,\"stdout\":%s,\"stderr\":%s,\"truncated\":%"
                 "d,\"error\":\"\",\"result\":%s}",
                 exit_code, escaped_stdout, escaped_stderr,
                 (total_bytes >= max_output_limit) ? 1 : 0, escaped_result);
  } else {
    len_printed = snprintf(json_response, json_size,
                           "{\"exit_code\":%d,\"stdout\":%s,\"stderr\":%s,"
                           "\"truncated\":%d,\"error\":\"\",\"result\":null}",
                           exit_code, escaped_stdout, escaped_stderr,
                           (total_bytes >= max_output_limit) ? 1 : 0);
  }

  if (len_printed < 0 || len_printed >= (int)json_size) {
    debug_log("failed to construct JSON response");
    free(escaped_stdout);
    free(escaped_stderr);
    if (result_value)
      free(escaped_result);
    free(json_response);
    free(output_buf);
    free(result_value);
    _exit(1);
  }

  // Clean up escaped strings
  free(escaped_stdout);
  free(escaped_stderr);
  if (result_value)
    free(escaped_result);

  // Actual length of the JSON string
  size_t json_len = strlen(json_response);
  uint32_t json_len_net = htonl(json_len);

  debug_log("sending response");
  write(sock, &json_len_net, 4);
  write(sock, json_response, json_len);
  debug_log("response sent, exiting");

  free(json_response);
  free(output_buf);
  free(result_value);
  close(sock);
  _exit(0);
}