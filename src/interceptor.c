#include "interceptor.h"

#include <string.h>

#include <dlfcn.h>
#include <pthread.h>
#include <syscall.h>

#include <sys/mman.h>

#include <backtrace.h>

#include <libsyscall_intercept_hook_point.h>

#include <x86linux/helper.h>

/* Static variables & functions */

static int _syscall_wrapper_essential(long, long, long, long, long, long, long,
                                      long *);
static void _disable_syscall_wrapper() {
  intercept_hook_point = _syscall_wrapper_essential;
}
static int _syscall_wrapper(long, long, long, long, long, long, long, long *);
static void _enable_syscall_wrapper() {
  intercept_hook_point = _syscall_wrapper;
}
static int _within_hook() {
  return intercept_hook_point == _syscall_wrapper ? 0 : 1;
}

static pthread_t _destruct_monitor(void **retval) {
  /* Try to start the operation. */
  const pthread_t __monitor = interceptor_tgstat.monitor;
  if (__monitor && __monitor != -1 &&
      __sync_val_compare_and_swap(&interceptor_tgstat.monitor, __monitor, -1) ==
          __monitor) {
    const int __within_hook = _within_hook();
    _disable_syscall_wrapper();

    /* This will invoke exit() syscall in the monitor thread. */
    log_verify_errno(pthread_cancel(__monitor));

    /* We need this stage to wait until the thread-related stats are updated. */
    log_verify(({
      int _ = pthread_join(__monitor, retval);
      _ == 0 || _ == EINVAL;
    }));

    if (!__within_hook)
      _enable_syscall_wrapper();
  }
  return __monitor;
}
static void _do_pre_exit_group() {
  size_t __nr_local_thread;
  do
    __nr_local_thread = interceptor_tgstat.nr_local_thread;
  while (__sync_val_compare_and_swap(&interceptor_tgstat.nr_local_thread,
                                     __nr_local_thread,
                                     0) != __nr_local_thread);
  __sync_fetch_and_sub(&interceptor_pgstat->nr_thread,
                       interceptor_tgstat.nr_local_thread);

  __sync_fetch_and_sub(&interceptor_pgstat->nr_tgrp, 1);
}
static volatile uint32_t _exit_futex;
static void _pre_exit_group_wrapper() {
  /*
   * It has to be a critical section, as it decreases
   * `interceptor_pgstat->nr_thread` with `interceptor_tgstat.nr_local_thread`
   * as well as decrement `interceptor_pgstat->nr_tgrp`.
   *
   * (should we use `USERSCHED_RESTART` here?)
   */
  log_verify_error(usersched_plock_pi(
      &_exit_futex, FUTEX_PRIVATE_FLAG | USERSCHED_RESTART,
      interceptor_tstat.tid, 100 * usersched_tsc_1us, NULL, NULL, NULL));

  _do_pre_exit_group();
}
static int _exit_group_wrapper(int status) {
  _pre_exit_group_wrapper();

  log_verify_error(usersched_punlock_pi(&_exit_futex, FUTEX_PRIVATE_FLAG,
                                        interceptor_tstat.tid, NULL));

  return interceptor_syscall(SYS_exit_group, status);
}
static int _exit_wrapper(int status) {
  /*
   * It has to be a critical section, as it decreases
   * `interceptor_pgstat->nr_thread`. (maybe `interceptor_pgstat->nr_tgrp` too)
   *
   * (should we use `USERSCHED_RESTART` here?)
   */
  log_verify_error(usersched_plock_pi(
      &_exit_futex, FUTEX_PRIVATE_FLAG | USERSCHED_RESTART,
      interceptor_tstat.tid, 100 * usersched_tsc_1us, NULL, NULL, NULL));

  const size_t __nr_local_thread =
      __sync_fetch_and_sub(&interceptor_pgstat->nr_thread, 1);
  if (pthread_self() != interceptor_tgstat.monitor && __nr_local_thread <= 2) {
  }

  log_verify_error(usersched_punlock_pi(&_exit_futex, FUTEX_PRIVATE_FLAG,
                                        interceptor_tstat.tid, NULL));

  return interceptor_syscall(SYS_exit, status);
}

/* See `asm/signal.h`.*/
struct kernel_sigaction {
  union {
    void (*kernel_sa_handler)(int);
    void (*kernel_sa_sigaction)(int, siginfo_t *, void *);
  } sigaction_handler;
  unsigned long sa_flags;
  void (*sa_restorer)();
  unsigned long sa_mask;
};
const size_t _sigsetsize = sizeof_elem(struct kernel_sigaction, sa_mask);
static volatile uint32_t _sigaction_futex;
static void _signal_wrapper(int, siginfo_t *, void *);
static __always_inline int
_rt_sigaction(int signum, const struct kernel_sigaction *restrict kact,
              struct kernel_sigaction *restrict oldkact, size_t sigsetsize) {
  return interceptor_syscall(SYS_rt_sigaction, signum, kact, oldkact,
                             sigsetsize);
}
/*
 * All local threads share the same sigaction.
 * (see `man 2 clone` about CLONE_SIGHAND, CLONE_VM, and CLONE_THREAD)
 */
static struct kernel_sigaction _orig_ksa[NSIG];
static int _rt_sigaction_wrapper(int signum,
                                 const struct kernel_sigaction *restrict kact,
                                 struct kernel_sigaction *restrict oldkact,
                                 size_t sigsetsize) {
  /* It is already AS-safe (i.e. all signal has been blocked; but why?). */

  log_verify(sigsetsize == _sigsetsize);

  /* Should we use `USERSCHED_RESTART` here? */
  log_verify_error(usersched_lock_pi(
      &_sigaction_futex, FUTEX_PRIVATE_FLAG | USERSCHED_RESTART,
      interceptor_tstat.tid, 100 * usersched_tsc_1us, NULL));

  struct kernel_sigaction __ksa;
  if (kact) {
    __ksa.sigaction_handler.kernel_sa_sigaction = _signal_wrapper;
    __ksa.sa_flags = kact->sa_flags | SA_SIGINFO;
    __ksa.sa_restorer = kact->sa_restorer;
    __ksa.sa_mask = kact->sa_mask;
  }

  int __ret = _rt_sigaction(signum, kact ? &__ksa : kact, oldkact, sigsetsize);
  if (!__ret) {
    /* Give the old sigaction to the user. */
    if (oldkact)
      memcpy(oldkact, &_orig_ksa[signum], sizeof(struct kernel_sigaction));

    /* Save the input sigaction as the original. */
    if (kact)
      memcpy(&_orig_ksa[signum], kact, sizeof(struct kernel_sigaction));
  }

  log_verify_error(usersched_unlock_pi(&_sigaction_futex, FUTEX_PRIVATE_FLAG,
                                       interceptor_tstat.tid));

  return __ret;
}

void *restrict __altstack;
static __attribute((hot)) int
_syscall_wrapper_essential(long syscall_number, long arg0, long arg1, long arg2,
                           long arg3, long arg4, long arg5,
                           long *restrict result) {
  /* No interceptable syscall() is allowed in this scope. */

  switch (syscall_number) {
  case SYS_exit:
    if ((*result = _exit_wrapper(arg0)) == -1)
      *result = -errno;
    break;
  case SYS_exit_group:
    if ((*result = _exit_group_wrapper(arg0)) == -1)
      *result = -errno;
    break;

  case SYS_rt_sigaction:
    if ((*result = _rt_sigaction_wrapper(arg0, address_cast(arg1),
                                         address_cast(arg2), arg3)) == -1)
      *result = -errno;
    break;

  case SYS_clone:
  case SYS_clone3:
  case SYS_rt_sigreturn:
  case SYS_vfork:
    /* These cannot be intercepted... Forward them to the kernel. */
    return 1;

  case SYS_sigaltstack:
    if (unlikely(__altstack)) {
      *result = -(errno = EPERM); // ?
      break;
    }
  default:
    /* Forward it to the kernel or _syscall_wrapper(). */
    return 2;
  }
  return 0;
}

static thread_local
    __attribute((tls_model("initial-exec"))) long _apply_futex_workaround;
static __attribute((hot)) int _syscall_wrapper(long syscall_number, long arg0,
                                               long arg1, long arg2, long arg3,
                                               long arg4, long arg5,
                                               long *restrict result) {
  /*
   * Intercept syscall instruction and save return value to `*result`.
   *
   * Return 0 to prohibit the original syscall from forwarding to the kernel.
   */

  /* Disable syscall interception. */
  _disable_syscall_wrapper();

  /* Call the essential part of the wrapper first. */
  int __forward = _syscall_wrapper_essential(syscall_number, arg0, arg1, arg2,
                                             arg3, arg4, arg5, result);
  if (unlikely(__forward < 2))
    return __forward;
  __forward = 0;

  if (unlikely(syscall_number == SYS_futex && _apply_futex_workaround)) {
    log_verify((arg1 == FUTEX_WAIT_PRIVATE && arg2 == 2 && !arg3) ||
               (arg1 == FUTEX_WAKE_PRIVATE && arg2 == 1));

    if (arg1 == FUTEX_WAIT_PRIVATE)
      log_verify(_apply_futex_workaround = arg0);
    else
      log_verify(_apply_futex_workaround == arg0);

    if (arg1 == FUTEX_WAIT_PRIVATE) {
      *(uint32_t *)arg0 = 0;
      *result = -(errno = 0); // ?
    }
  } else {
    /*
     * Forward to the user hook (if possible).
     *
     * Currently, we do not check `__forward` value before saving to `*result`.
     */
    long (*const __syscall_hook)(long, long, long, long, long, long, long,
                                 int *) = interceptor_syscall_hook;
    if (likely(__syscall_hook)) {
      if ((*result = __syscall_hook(syscall_number, arg0, arg1, arg2, arg3,
                                    arg4, arg5, &__forward)) == -1)
        *result = -errno;
    } else
      __forward = 1;
  }

  /* Enable syscall interception again. */
  _enable_syscall_wrapper();

  return __forward;
}

static int _print_addr2line(void *restrict data, uintptr_t pc,
                            const char *restrict filepath, int line,
                            const char *restrict func) {
  log(value_cast(data, int), "at 0x%lx: %s (%s:%d)", pc, func,
      filename(filepath), line);
  return 0;
}
static void _default_handler(int sig, const siginfo_t *restrict info,
                             const void *restrict context) {
  const ucontext_t *const restrict __u = context;
  const long long __pc = __u->uc_mcontext.gregs[REG_RIP];
  Dl_info __info;
  dladdr(address_cast(__pc), &__info);
  log(LOG_EMERG,
      "--- SIG%s (%s) {si_code=%d, si_addr=%p, si_pid=%d, dli_fname=%s} ---",
      sigabbrev_np(sig), sigdescr_np(sig), info->si_code, info->si_addr,
      info->si_pid, __info.dli_fname);

  struct backtrace_state *const restrict __state =
      backtrace_create_state(NULL, 0, NULL, NULL);
  backtrace_pcinfo(__state, __pc, _print_addr2line, NULL, LOG_EMERG);
  log_backtrace(LOG_EMERG);
}
static int __attribute((const)) _is_ign_sig(int sig) {
  switch (sig) {
  case SIGCHLD:
  case SIGURG:
  case SIGWINCH:
    return 1;
  }
  return 0;
}
static int __attribute((const)) _is_term_sig(int sig) {
  if (_is_ign_sig(sig))
    return 0;
  switch (sig) {
  case SIGCONT:
  case SIGSTOP:
  case SIGTSTP:
  case SIGTTIN:
  case SIGTTOU:
    return 0;
  }
  return 1;
}
static __attribute((hot)) void
_signal_wrapper(int sig, siginfo_t *restrict info, void *restrict context) {
  const int __within_hook = _within_hook();
  /* Disable syscall interception. */
  _disable_syscall_wrapper();

  /* Call user signal hook first (if possible). */
  int __forward = 0;
  void (*const __signal_hook)(int, siginfo_t *, void *, int *) =
      interceptor_signal_hook;
  if (likely(__signal_hook))
    __signal_hook(sig, info, context, &__forward);
  else
    __forward = 1;

  if (__forward) {
    /*
     * Critical section to copy the original sigaction to the local variable.
     *
     * Do not block signals here for optimization.
     * (sigaction() is already AS-safe (for some reason) so there will be no
     * deadlock if we do not delay in this scope)
     */
    log_verify_error(usersched_lock_pi(
        &_sigaction_futex, FUTEX_PRIVATE_FLAG | USERSCHED_RESTART,
        interceptor_tstat.tid, 100 * usersched_tsc_1us, NULL));

    struct kernel_sigaction __ksa;
    memcpy(&__ksa, &_orig_ksa[sig], sizeof(struct kernel_sigaction));

    /* Check for SA_RESETHAND. */
    if (__ksa.sa_flags & SA_RESETHAND)
      /* Do NOT reset `sa_flags` here! (since it is the confirmed behavior) */
      _orig_ksa[sig].sigaction_handler.kernel_sa_sigaction = NULL;

    log_verify_error(usersched_unlock_pi(&_sigaction_futex, FUTEX_PRIVATE_FLAG,
                                         interceptor_tstat.tid));

    if (unlikely(!__ksa.sigaction_handler.kernel_sa_sigaction)) {
      _default_handler(sig, info, context);

      /* Modify thread-related stats first. */
      if (_is_term_sig(sig))
        _pre_exit_group_wrapper();

      /* User did not set signal handler; Use default signal handler for now. */
      __ksa.sigaction_handler.kernel_sa_handler = SIG_DFL;
      log_verify_error(_rt_sigaction(sig, &__ksa, NULL, _sigsetsize));

      /* Unblock this signal first, then raise it. */
      sigset_t __ss = {0}, __oss;
      log_verify_error(sigaddset(&__ss, sig));
      log_verify_errno(pthread_sigmask(SIG_UNBLOCK, &__ss, &__oss));
      log_verify_error(raise(sig));

      /* Restore previous signal mask and sigaction. */
      log_verify_errno(pthread_sigmask(SIG_SETMASK, &__oss, NULL));
      __ksa.sigaction_handler.kernel_sa_sigaction = _signal_wrapper;
      log_verify_error(_rt_sigaction(sig, &__ksa, NULL, _sigsetsize));
    } else {
      /* Call the saved custom signal handler. */
      _enable_syscall_wrapper();
      __ksa.sigaction_handler.kernel_sa_sigaction(sig, info, context);
      _disable_syscall_wrapper();
    }
  }

  /* Enable syscall interception again (if required). */
  if (!__within_hook)
    _enable_syscall_wrapper();
}

/* clone() wrappers */

static __attribute((hot)) void _clone_wrapper_child() {
  const pid_t __parent_tgid = interceptor_tgstat.tgid;
  interceptor_tgstat.tgid = getpid();

  __sync_add_and_fetch(&interceptor_pgstat->nr_thread, 1);
  const int __forked = interceptor_tgstat.tgid != __parent_tgid;
  if (__forked) {
    __sync_add_and_fetch(&interceptor_pgstat->nr_tgrp, 1);

    interceptor_tgstat.nr_local_thread = 1;
    interceptor_tgstat.monitor = 0;

    _exit_futex = _sigaction_futex = 0;
    barrier(); // ?
  } else {
    size_t __nr_local_thread;
    do
      if ((__nr_local_thread = interceptor_tgstat.nr_local_thread))
        pause(); // Do not allow to proceed.
    while (__sync_val_compare_and_swap(
               &interceptor_tgstat.nr_local_thread, __nr_local_thread,
               __nr_local_thread + 1) != __nr_local_thread);
  }

  interceptor_tstat.tid = gettid();
  interceptor_tstat.thread_nr =
      __sync_add_and_fetch(&interceptor_pgstat->cnt_thread, 1);

  void *__ret = NULL;
  void *(*const __clone_hook_child)(pid_t) = interceptor_clone_hook_child;
  if (likely(__clone_hook_child))
    __ret = __clone_hook_child(__parent_tgid);

  if (__forked) {
    /* Start a new instance of thread group monitor (if possible). */
    void *(*const __monitor_fn)(void *) = interceptor_monitor_fn;
    if (likely(__monitor_fn))
      interceptor_attach_monitor(interceptor_monitor_attr, __monitor_fn, __ret);
  }

  /* Reinitialize TLS variable. */
  _enable_syscall_wrapper();
}
static __attribute((hot)) void _clone_wrapper_parent(long child_tid) {
  void (*const __clone_hook_parent)(pid_t) = interceptor_clone_hook_parent;
  if (likely(__clone_hook_parent)) {
    /* Disable syscall interception. */
    _disable_syscall_wrapper();

    __clone_hook_parent(child_tid);

    /* Enable syscall interception again. */
    _enable_syscall_wrapper();
  }
}

/* Initialization */

int __valgrind;
static void _signal_wrapper_init() {
  const char *__env = getenv("INTERCEPTOR_ALTSTACK");
  const int __sa_flags = SA_SIGINFO | (__env ? SA_ONSTACK : 0);

  /* Set our signal wrapper as handler for all signals. */
  for (int i = 1; i < NSIG; ++i) {
    /*
     * Exclude non-interceptable and ignored signals at initialization time.
     * (also, see https://www.man7.org/linux/man-pages/man7/nptl.7.html)
     */
    if (likely((i <= SIGSYS || i >= SIGRTMIN) && i != SIGKILL && i != SIGSTOP &&
               !_is_ign_sig(i))) {
      struct sigaction __osa;
      log_verify_error(sigaction(i, NULL, &__osa));

      /*
       * (workaround for valgrind)
       * Omit `SIGRTMAX` interception if another sigaction is already installed.
       */
      if (likely(i == SIGRTMAX && __osa.sa_sigaction))
        __valgrind = 1;
      else {
        _orig_ksa[i].sigaction_handler.kernel_sa_sigaction = __osa.sa_sigaction;
        _orig_ksa[i].sa_flags = __osa.sa_flags;
        _orig_ksa[i].sa_restorer = __osa.sa_restorer; // not used
        static_assert(sizeof(_orig_ksa[i].sa_mask) ==
                      sizeof(__osa.sa_mask.__val[0]));
        _orig_ksa[i].sa_mask = __osa.sa_mask.__val[0];

        /* Update the sigaction. */
        __osa.sa_sigaction = _signal_wrapper;
        __osa.sa_flags |= __sa_flags;
        log_verify_error(sigaction(i, &__osa, NULL));
      }
    }
  }

  if (__env) {
    size_t __altstack_size;
    log_verify_error(__altstack_size = strtoul(__env, NULL, 0));
    log_verify_error(__altstack = malloc(__altstack_size));
    const stack_t __ss = {
        .ss_size = __altstack_size,
        .ss_sp = __altstack,
#define SS_AUTODISARM (1U << 31) // See `linux/signal.h`.
        .ss_flags = __valgrind ? 0 : SS_AUTODISARM,
    };
    log_verify_error(sigaltstack(&__ss, NULL));
  }
}
static __attribute((constructor(101))) void _constructor() {
  /* Do not initialize if interceptor_allowed() returns 0. */
  if (interceptor_allowed()) {
    usersched_init(0);

    log_verify_error(interceptor_pgstat =
                         mmap(NULL, sizeof(*interceptor_pgstat),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    /* No need to do memset() here; MAP_ANONYMOUS guarantees zeroed memory. */
    interceptor_pgstat->cnt_thread = interceptor_pgstat->nr_tgrp =
        interceptor_pgstat->nr_thread = 1;

    interceptor_tgstat.tgid = getpid();
    interceptor_tgstat.nr_local_thread = 1;

    interceptor_tstat.tid = gettid();
    interceptor_tstat.thread_nr = 1;

    /* Initialize signal interception. */
    _signal_wrapper_init();

    intercept_hook_point_clone_child = _clone_wrapper_child;
    intercept_hook_point_clone_parent = _clone_wrapper_parent;

    /* Start system call interception. */
    _enable_syscall_wrapper();

    /* Try early creation of new monitor thread if (somehow) possible. */
    void *(*const __monitor_fn)(void *) = interceptor_monitor_fn;
    if (__monitor_fn)
      interceptor_attach_monitor(interceptor_monitor_attr, __monitor_fn, NULL);
  }
}

/* Variables for signal & system call interception */

typeof(interceptor_syscall_hook) interceptor_syscall_hook;

typeof(interceptor_signal_hook) interceptor_signal_hook;

typeof(interceptor_clone_hook_child) interceptor_clone_hook_child;
typeof(interceptor_clone_hook_parent) interceptor_clone_hook_parent;

typeof(interceptor_monitor_attr) interceptor_monitor_attr;
typeof(interceptor_monitor_fn) interceptor_monitor_fn;

typeof(interceptor_pgstat) interceptor_pgstat;
typeof(interceptor_tgstat) interceptor_tgstat;
thread_local __attribute((
    tls_model("initial-exec"))) typeof(interceptor_tstat) interceptor_tstat;

/* Public functions */

long interceptor_syscall(long syscall_number, ...) {
  va_list __ap;
  va_start(__ap, syscall_number);

  register long __ret asm("rax") = syscall_number;
  register long __arg0 asm("rdi") = va_arg(__ap, long);
  register long __arg1 asm("rsi") = va_arg(__ap, long);
  register long __arg2 asm("rdx") = va_arg(__ap, long);
  register long __arg3 asm("r10") = va_arg(__ap, long);
  register long __arg4 asm("r8") = va_arg(__ap, long);
  register long __arg5 asm("r9") = va_arg(__ap, long);

  va_end(__ap);

  asm volatile("syscall"
               : "=a"(__ret)
               : "0"(__ret), "D"(__arg0), "S"(__arg1), "d"(__arg2), "r"(__arg3),
                 "r"(__arg4), "r"(__arg5)
               : "rcx", "r11", "memory");

  return unlikely(errno = syscall_error_code(__ret)) ? -1 : __ret;
}

/* Functions for thread group monitor */

pthread_t interceptor_attach_monitor(const pthread_attr_t *restrict attr,
                                     void *(*monitor_fn)(void *),
                                     void *restrict arg) {
  pthread_t __monitor =
      __sync_val_compare_and_swap(&interceptor_tgstat.monitor, 0, -1);
  if (likely(!__monitor)) {
    const int __within_hook = _within_hook();

    /* Ensure the futex workaround is applied in this scope only. */
    as_enter();
    _apply_futex_workaround = 1;
    _enable_syscall_wrapper();

    /* Attach the new monitor thread. */
    log_verify_errno(pthread_create(&__monitor, attr, monitor_fn, arg));

    if (__within_hook)
      _disable_syscall_wrapper();
    _apply_futex_workaround = 0;
    as_exit();

    interceptor_tgstat.monitor = __monitor;
    barrier(); // ?
  }
  return __monitor;
}
pthread_t interceptor_destruct_monitor(void **retval) {
  /* Try to start the operation. */
  const pthread_t __monitor = _destruct_monitor(retval);

  /* Mark that the operation is completed. */
  if (__monitor == interceptor_tgstat.monitor) {
    interceptor_tgstat.monitor = 0;
    barrier(); // ?
  }

  return __monitor;
}

int interceptor_allowed() {
  /*
   * Support clang's ASAN: Check if the program name is
   * `llvm-symbolizer-<VERSION>`.
   */
  return syscall_hook_in_process_allowed() &&
         !strstr(program_invocation_short_name, "llvm-symbolizer-");
}
