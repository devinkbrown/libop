/*
 * libop: ophion support library.
 * op_seccomp.h: seccomp-bpf privilege restriction and secure memory for daemons.
 *
 * Two sandboxing strategies:
 *
 *   op_seccomp_lockdown()       — deny-exec/fork/ptrace filter for short-lived
 *                                  helper daemons that never spawn children (ssld,
 *                                  wsockd, authproc).  All other syscalls
 *                                  are allowed by default, with two argument-filtered
 *                                  exceptions:
 *                                    • mmap(2) / mprotect(2): killed if PROT_EXEC is
 *                                      set in the prot argument (W^X enforcement).
 *                                      After lockdown all code is already loaded;
 *                                      there is no legitimate reason to make memory
 *                                      executable at runtime.  This eliminates
 *                                      shellcode injection, JIT engine abuse, and
 *                                      GOT-overwrite-to-exec attack chains.
 *
 *   op_seccomp_lockdown_shim()  — shim-appropriate filter for the long-lived socket-
 *                                  keeper process (ophion-shim).  Unlike the base
 *                                  lockdown, fork/execve/clone are ALLOWED (required
 *                                  to launch and restart the ircd binary).  In
 *                                  exchange the filter adds:
 *                                    • socket(2) argument check: only AF_UNIX sockets
 *                                      may be created after init; AF_INET/AF_INET6 and
 *                                      all other domains are killed.
 *                                    • connect(2): denied entirely — the shim never
 *                                      initiates outbound connections.
 *                                    • mmap(2) / mprotect(2): W^X enforcement same as
 *                                      the base lockdown.  execve(2) maps code inside
 *                                      the kernel and is unaffected by this check.
 *
 * Two secure-memory primitives:
 *
 *   op_shim_harden()            — early process hardening for ophion-shim: disables
 *                                  core dumps (PR_SET_DUMPABLE 0 + RLIMIT_CORE=0),
 *                                  becomes subreaper (PR_SET_CHILD_SUBREAPER), and
 *                                  sets PR_SET_NO_NEW_PRIVS so that privilege
 *                                  escalation via setuid/setgid exec is permanently
 *                                  prevented even if the seccomp filter is unavailable.
 *                                  Call before bind_listeners and launch_core.
 *
 *   op_secure_alloc(len)        — layered secure allocation: tries memfd_secret(2)
 *                                  first (Linux ≥ 5.14, kernel-isolated, invisible to
 *                                  /proc/PID/mem and ptrace); falls back to anonymous
 *                                  mmap + MADV_WIPEONFORK + MADV_DONTDUMP + mlock().
 *                                  Use for session state blobs, TLS keys, passwords.
 *
 *   op_secure_free(p, len)      — explicit_bzero the region, then munmap.  Minimises
 *                                  the window during which sensitive bytes remain in
 *                                  process memory after the data is no longer needed.
 *
 * On non-Linux platforms all four functions are no-ops or thin wrappers around
 * mmap/munmap/free that are safe to call unconditionally.
 *
 * On Linux without BPF support (kernel < 3.5 or CONFIG_SECCOMP_FILTER=n) the
 * lockdown functions return -1 and set errno; the caller may ignore this and
 * continue with reduced sandboxing.
 */

#ifndef OP_SECCOMP_H
#define OP_SECCOMP_H

#include <stddef.h>   /* size_t */

/* ── Syscall filters ──────────────────────────────────────────────────────── */

/*
 * op_seccomp_lockdown — install the deny-exec/fork/ptrace BPF filter.
 *
 * Kills the process (SECCOMP_RET_KILL_PROCESS) on any attempt to call:
 *   exec:    execve, execveat
 *   fork:    fork, vfork, clone, clone3
 *   debug:   ptrace, process_vm_readv, process_vm_writev
 *   kernel:  kexec_load, kexec_file_load, bpf
 *   keyring: keyctl, add_key, request_key
 *   ns:      unshare, setns, pivot_root
 *   perf:    perf_event_open
 *   uring:   io_uring_setup, io_uring_enter, io_uring_register
 *   misc:    userfaultfd, modify_ldt, nfsservctl
 *   W^X:     mmap(PROT_EXEC), mprotect(PROT_EXEC)  [argument-filtered]
 *
 * All other syscalls are allowed.
 *
 * Returns  0  on success.
 * Returns -1  on failure (errno set); caller may ignore and continue.
 */
int op_seccomp_lockdown(void);

/*
 * op_seccomp_lockdown_shim — install the shim-specific BPF filter.
 *
 * Like op_seccomp_lockdown() but tailored for the ophion-shim process:
 *
 *   ALLOWED (unlike base lockdown): fork, vfork, clone, clone3, execve, execveat.
 *   The shim must be able to fork+exec the ircd binary and restart it on crash.
 *
 *   ADDED restrictions:
 *     • socket(domain, ...): killed unless domain == AF_UNIX (1).  Prevents
 *       the shim from opening new TCP/UDP network sockets after startup.
 *       socketpair(2) is a separate syscall and is unaffected.
 *     • connect(2): always killed.  The shim never initiates outbound
 *       connections; all its sockets come from socketpair() or are inherited.
 *
 *   STILL DENIED: ptrace, process_vm_readv/writev, kexec_*, bpf, keyctl,
 *   add_key, request_key, unshare, setns, pivot_root, perf_event_open,
 *   io_uring_*, userfaultfd, modify_ldt, nfsservctl, and mmap/mprotect
 *   with PROT_EXEC (W^X enforcement — see op_seccomp_lockdown comment).
 *
 * Returns  0  on success.
 * Returns -1  on failure (errno set); caller may ignore and continue.
 */
int op_seccomp_lockdown_shim(void);

/*
 * op_shim_harden — early process-level hardening for the shim.
 *
 * Call at the very start of main(), before binding listeners or launching
 * any child process.  Three measures applied:
 *
 *   Linux:   PR_SET_DUMPABLE 0    — no core dumps while session key blobs
 *                                    may be in memory (crash during /UPGRADE
 *                                    would otherwise dump all TLS session keys
 *                                    to disk in plaintext).  Also prevents
 *                                    /proc/PID/mem writes by other processes.
 *            RLIMIT_CORE = 0      — belt-and-suspenders; prevents core files
 *                                    even if dumpable is reset by a child exec.
 *            PR_SET_CHILD_SUBREAPER 1 — orphaned ircd grandchildren (e.g.
 *                                    authproc's curl/wget download children)
 *                                    reparent to the shim rather than PID 1.
 *            PR_SET_NO_NEW_PRIVS 1 — permanently prevent privilege escalation
 *                                    via setuid/setgid/fcaps exec, even if the
 *                                    seccomp filter is unavailable on this kernel.
 *                                    Idempotent; also applied inside lockdown.
 *
 *   FreeBSD: RLIMIT_CORE = 0 + PROC_REAP_ACQUIRE (subreaper equivalent).
 *   OpenBSD/macOS: RLIMIT_CORE = 0 only.
 *   Windows: audit-mode child process policy + standard mitigations.
 *   Other:   no-op, returns 0.
 *
 * Returns 0 if all applicable measures succeeded, -1 if any failed.
 * Partial success still applies; non-fatal, but log the result.
 */
int op_shim_harden(void);

/* ── Secure memory ────────────────────────────────────────────────────────── */

/*
 * op_secure_alloc — allocate `len` bytes of zeroed, fork-safe memory.
 *
 * Uses mmap(MAP_PRIVATE|MAP_ANONYMOUS) rather than malloc so the region is
 * page-aligned and can be passed to madvise(MADV_WIPEONFORK).  On Linux ≥ 4.14
 * MADV_WIPEONFORK is applied automatically: any fork() of this process will
 * see a zeroed copy of the region rather than the original contents.  This
 * prevents session key blobs from leaking into unexpected child processes (e.g.
 * if an attacker triggers a fork via an exploit after lockdown).
 *
 * Returns a pointer to the region on success, NULL on failure.
 * The returned memory is always writable and zeroed on first use.
 */
void *op_secure_alloc(size_t len);

/*
 * op_secure_free — securely release memory returned by op_secure_alloc().
 *
 * Calls explicit_bzero(p, len) before munmap() to overwrite sensitive bytes
 * before they are returned to the OS.  This minimises the window during which
 * key material lingers in pages that may be recycled by future mmap calls.
 *
 * `len` must equal the value originally passed to op_secure_alloc().
 * Safe to call with p == NULL (no-op).
 */
void op_secure_free(void *p, size_t len);

#endif /* OP_SECCOMP_H */
