#pragma once

#ifdef __cplusplus
#include <csignal>
#include <cstdint>
#else
#include <signal.h>
#include <stdint.h>

#include <threads.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GLIBC syscall()-like hooking function
 *
 * The input parameters are for raw syscall instruction.
 * Do NOT use those with the original GLIBC's syscall() wrapper function!
 *
 * Save 1 to `*forward` to execute the original syscall when returning.
 *
 * Currently, the following system calls cannot be hooked: clone(), clone3(),
 * exit(), exit_group(), rt_sigaction(), rt_sigreturn() and vfork().
 *
 * For interception:
 * Upon error, save appropriate `errno` value to it and return -1.
 */
extern long (*interceptor_syscall_hook)(long syscall_number, long arg0,
                                        long arg1, long arg2, long arg3,
                                        long arg4, long arg5,
                                        int *restrict forward);

/*
 * Signal handler hooking function
 *
 * Save 1 to `*forward` to call the original signal handler when returning.
 */
extern void (*interceptor_signal_hook)(int sig, siginfo_t *info, void *context,
                                       int *restrict forward);

/* Its return value will be used as `arg` for the new monitor thread. */
extern void *(*interceptor_clone_hook_child)(pid_t parent_tgid);
extern void (*interceptor_clone_hook_parent)(pid_t child_tid);

extern pthread_attr_t *interceptor_monitor_attr;
/* If set, a new monitor thread will be created for each new thread group. */
extern void *(*interceptor_monitor_fn)(void *arg);

extern volatile struct {
  /* Global counter of total thread(s); It will NOT be decremented. */
  size_t cnt_thread;

  size_t nr_tgrp;
  size_t nr_thread;
} *restrict interceptor_pgstat;
extern struct {
  pid_t tgid;

  /* Number of thread(s) in this thread group including the monitor thread */
  volatile size_t nr_local_thread;

  /* 0 == (no running thread group monitor yet) */
  volatile pthread_t monitor;
} interceptor_tgstat;
extern thread_local __attribute((tls_model("initial-exec"))) struct {
  pid_t tid;

  size_t thread_nr;
} interceptor_tstat;

/*
 * Raw syscall wrapper function
 *
 * It still behaves like GLIBC's syscall() for return value or `errno` handling.
 */
long interceptor_syscall(long syscall_number, ...);

/*
 * Attach monitor thread for this thread group.
 *
 * The monitor thread will be terminated by pthread_cancel() when there is no
 * other thread in the thread group.
 *
 * If successful (or there is an already running monitor thread), return the
 * `pthread_t` value of the monitor thread. If interceptor_*_monitor() was in
 * progress, return -1.
 */
pthread_t interceptor_attach_monitor(const pthread_attr_t *restrict attr,
                                     void *(*monitor_fn)(void *),
                                     void *restrict arg) __nonnull((2));
#define INTERCEPTOR_ATTACH_MONITOR_NOW(arg)                                    \
  interceptor_attach_monitor(interceptor_monitor_attr, interceptor_monitor_fn, \
                             arg)
/*
 * It will call pthread_cancel() to terminate the monitor thread.
 *
 * If successful, return the `pthread_t` value of the terminated thread (0 if
 * there was no monitor thread). If interceptor_*_monitor() was in progress,
 * return -1.
 */
pthread_t interceptor_destruct_monitor(void **retval);

/* Return 1 if libinterceptor is allowed to function. */
int interceptor_allowed();

#ifdef __cplusplus
}
#endif
