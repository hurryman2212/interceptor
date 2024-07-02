# interceptor

Preloading Library for Userspace Syscall Instruction, Signal, and Thread Interception

You need [the special version of libsyscall_intercept](https://github.com/hurryman2212/syscall_intercept) using the TLS (thread local storage) function pointer variable for hooking. Additionally, you need [libx86linuxextra](https://github.com/hurryman2212/x86linuxextra) as a dependency.

This currently supports x86-64 Linux only due to its code and dependency on libsyscall_intercept and libx86linuxextra. It is a library intended to be used as a 'preloaded' one via `LD_PRELOAD`.

## How to Install

```sh
mkdir -p build
cd build
cmake .. # -DCMAKE_GENERATOR=Ninja -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install -j$(nproc)
```

## Usage

Please refer to `include/interceptor.h`.

## Example

Build your library to be preloaded via `LD_PRELOAD` and set the hooking function pointer values.

```c
#include <string.h>

#include <libaudit.h>

#include <x86linux/helper.h>

#include <interceptor.h>

static void signal_hook(int sig, siginfo_t *info, void *context,
                        int *restrict forward) {
  log(LOG_WARNING, "[Thread #%lu] SIG%s", interceptor_tstat.thread_nr,
      sigabbrev_np(sig));
  *forward = 1;
}

static long syscall_hook(long syscall_number, long arg0, long arg1, long arg2,
                         long arg3, long arg4, long arg5,
                         int *restrict forward) {
  long ret = 0;
  int errno_save = 0;

  switch (syscall_number) {
  default:
    ret =
        interceptor_syscall(syscall_number, arg0, arg1, arg2, arg3, arg4, arg5);
    if (ret == -1) {
      errno_save = errno;
      log(LOG_ERR,
          "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx %s (%s)",
          audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1, arg2,
          arg3, arg4, arg5, ret, strerrorname_np(errno_save),
          strerrordesc_np(errno_save));
    } else
      log(LOG_DEBUG, "%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = 0x%lx",
          audit_syscall_to_name(syscall_number, MACH_86_64), arg0, arg1, arg2,
          arg3, arg4, arg5, ret);
  };

  if (!*forward)
    errno = errno_save;
  return ret;
}

static void *tracker(void *dummy) {
  log(LOG_NOTICE, "[Thread #%lu] PID/TGID: %d / Tracker TID: %d",
      interceptor_tstat.thread_nr, interceptor_tgstat.tgid,
      interceptor_tstat.tid);
  while (1) {
    log(LOG_INFO, "[Thread #%lu] # of active thread(s): %lu",
        interceptor_tstat.thread_nr, interceptor_pgstat->nr_thread);
    log(LOG_INFO, "[Thread #%lu] # of active thread group(s): %lu",
        interceptor_tstat.thread_nr, interceptor_pgstat->nr_tgrp);
    log(LOG_INFO, "[Thread #%lu] # of active local thread(s): %lu",
        interceptor_tstat.thread_nr, interceptor_tgstat.nr_local_thread);
    log(LOG_INFO, "[Thread #%lu] Thread counter (increment-only): %lu",
        interceptor_tstat.thread_nr, interceptor_pgstat->cnt_thread);
    sleep(1);
  }
  return NULL;
}

static __attribute((constructor(102))) void hook_constructor() {
  if (interceptor_allowed()) {
    LOG_INIT();
    const char *env = getenv("LOG_LVL");
    log_enable(env ? atoi(env) : LOG_DEBUG);

    interceptor_syscall_hook = syscall_hook;
    interceptor_signal_hook = signal_hook;

    interceptor_monitor_fn = tracker;

    INTERCEPTOR_ATTACH_MONITOR_NOW(NULL);
  }
}
```

## (current) Limitation

1. Since it is not possible to prevent `ptrace()` by another thread (when there is enough permission), there is no way to prevent `syscall` instruction execution by `ptrace(PTRACE_SETREGS, ...); ...`.
2. Due to some system calls that get interrupted only when there is no handler for that signal (`ERESTARTNOHAND`), libinterceptor does not install the interception routine for signals ignored by default (`SIGCHLD`, `SIGURG`, and `SIGWINCH`) when initializing. Since `SIGCHLD` is not handled when the original program does not install its signal handler, the signal wrapper manages the update of global thread-related stats (`interceptor_pgstat`; but it also updates `interceptor_tgstat` and `interceptor_tstat` as) when a thread is terminated by terminating signals. Even with the `SIGCHLD` handler installed, the issue is still valid if there is no parent process to manage the stats for that thread group where the thread terminated by `SIGKILL` is. Also, if the whole child thread group terminates with a single signal incoming, `SIGCHLD` only provides information about the thread group leader. **Due to these reasons, the default `SIGCHLD` interception routine is currently not implemented.**
3. There are some system calls that can affect the state of another thread like `prlimit64()`. If this kind of system call is executed in a remote thread, this cannot be handled too.
