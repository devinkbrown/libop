/*
 * libop: ophion support library.
 * seccomp.c: seccomp-bpf privilege restriction and secure memory for daemons.
 *
 * op_seccomp_lockdown() — deny-exec/fork/ptrace filter for helper daemons.
 * op_seccomp_lockdown_shim() — shim-appropriate filter (fork/exec allowed;
 *                              socket domain filter + connect deny added).
 * op_secure_alloc() / op_secure_free() — MADV_WIPEONFORK secure memory.
 *
 * op_seccomp_lockdown() installs a BPF filter that:
 *
 *   1. Verifies the syscall was issued from the expected 64-bit ABI.
 *      Without this check a 32-bit payload on x86_64 can bypass the
 *      deny-list: i386 __NR_execve is 11, not 59, so the x86_64 check
 *      simply doesn't match and the exec proceeds.
 *
 *   2. Kills the process (SECCOMP_RET_KILL_PROCESS) if it attempts any
 *      of the following after lockdown:
 *        exec:    execve, execveat
 *        fork:    fork, vfork, clone, clone3
 *        debug:   ptrace, process_vm_readv, process_vm_writev
 *        kernel:  kexec_load, kexec_file_load, bpf
 *        keyring: keyctl, add_key, request_key
 *        ns:      unshare, setns, pivot_root
 *        perf:    perf_event_open
 *        uring:   io_uring_setup, io_uring_enter, io_uring_register
 *        sched:   sched_setscheduler, sched_setattr
 *        mount:   mount, open_tree, move_mount, fsopen, fsconfig,
 *                 fsmount, fspick, open_tree_attr
 *        memory:  mseal
 *
 *   3. Allows all other syscalls.
 *
 * Installation prefers the seccomp(2) syscall with TSYNC (applies the
 * filter to all threads atomically) and falls back to prctl(PR_SET_SECCOMP)
 * on older kernels.
 *
 * Linux only.  Other platforms compile a no-op stub.
 */

#ifdef __linux__

#include <op_seccomp.h>
#include <errno.h>
#include <stddef.h>      /* offsetof, size_t */
#include <stdint.h>      /* uint8_t */
#include <string.h>      /* explicit_bzero */
#include <unistd.h>      /* syscall(), ftruncate */
#include <sys/mman.h>    /* mmap, munmap, madvise, mlock, MADV_* */
#include <sys/prctl.h>
#include <sys/resource.h> /* setrlimit, RLIMIT_CORE */
#include <sys/syscall.h>
#include <sys/socket.h>  /* AF_UNIX */
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#define HAVE_SYS_RESOURCE_H 1

/*
 * BPF helper macros — identical to those in linux/filter.h but
 * reproduced here so we don't rely on the kernel header exporting
 * BPF_STMT / BPF_JUMP (some distros guard them behind _KERNEL_).
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, (unsigned int)(k) }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) \
    { (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) }
#endif

/*
 * Map the build-time architecture to the corresponding AUDIT_ARCH_*
 * constant.  If the architecture is not listed here the arch check is
 * omitted (the deny-list will still work but without the ABI bypass
 * guard).
 */
#if   defined(__x86_64__)
# define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__powerpc64__)
# ifdef __LITTLE_ENDIAN__
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_PPC64LE
# else
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_PPC64
# endif
#elif defined(__s390x__)
# define SECCOMP_AUDIT_ARCH AUDIT_ARCH_S390X
#elif defined(__riscv) && (__riscv_xlen == 64)
# ifdef AUDIT_ARCH_RISCV64
#  define SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV64
# endif
#endif

/*
 * install_seccomp_filter — install a sock_fprog with TSYNC and graceful
 * fallback through three kernel generations:
 *
 *   1. seccomp(TSYNC|TSYNC_ESRCH) — Linux 5.7+: atomically syncs filter to
 *      all threads; distinguishes "thread refused sync" (ESRCH) from "unknown
 *      flag" (EINVAL), enabling clean retry without ambiguity.
 *
 *   2. seccomp(TSYNC) — Linux 3.17–5.6: atomically syncs to all threads but
 *      cannot tell EINVAL-from-flag from EINVAL-from-thread.
 *
 *   3. prctl(PR_SET_SECCOMP) — Linux 3.5+: per-thread only; adequate for
 *      single-threaded daemons.
 *
 * Returns 0 on success, -1 on failure (errno set).
 */
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
# define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1UL << 4)
#endif

static int
install_seccomp_filter(struct sock_fprog *prog)
{
#if defined(__NR_seccomp) && defined(SECCOMP_SET_MODE_FILTER) && \
    defined(SECCOMP_FILTER_FLAG_TSYNC)
    /* TSYNC_ESRCH first (Linux ≥ 5.7). */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
                prog) == 0)
        return 0;
    /* TSYNC without ESRCH (Linux 3.17–5.6). */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, prog) == 0)
        return 0;
#endif
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0 ? -1 : 0;
}

/*
 * DENY_SYSCALL(nr) — two BPF instructions that kill the process when
 * the accumulator equals `nr`, otherwise fall through to the next check.
 *
 *   BPF_JEQ jt=0 jf=1: if equal → next instr (KILL), else skip KILL.
 */
#define DENY_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/*
 * DENY_IF_FLAG_SET(syscallnr, argidx, mask) — seven BPF instructions that
 * kill the process if the argument at `argidx` has any bit in `mask` set.
 * Otherwise the syscall is allowed and the accumulator (syscall nr) is
 * restored so subsequent filter rules can inspect it.
 *
 * Layout (A = index of first instruction):
 *
 *   [A]   JEQ syscallnr, 0, 5 — not this syscall: skip 5 to [A+6] (LD nr)
 *   [A+1] LD  args[argidx]    — load the argument to test
 *   [A+2] AND mask             — isolate the flags we care about
 *   [A+3] JEQ 0, 1, 0         — none set → skip 1 to [A+5] ALLOW; else → KILL
 *   [A+4] RET KILL             — forbidden flag(s) set
 *   [A+5] RET ALLOW            — call is permitted
 *   [A+6] LD  nr               — not this syscall: reload accumulator
 *
 * Used by the derived macros below and directly for clone namespace guards.
 */
#define DENY_IF_FLAG_SET(syscallnr, argidx, mask) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (syscallnr), 0, 5), \
    BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, \
             (unsigned int)offsetof(struct seccomp_data, args[(argidx)])), \
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, (unsigned int)(mask)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    BPF_STMT(BPF_LD  | BPF_W  | BPF_ABS, \
             (unsigned int)offsetof(struct seccomp_data, nr))

/*
 * DENY_IF_PROT_EXEC(syscallnr) — kill if the prot argument (args[2]) has
 * PROT_EXEC set.  Applies to mmap(2), mprotect(2), and pkey_mprotect(2),
 * all of which place prot at the third argument position.
 *
 * Rationale: after lockdown all code is already mapped.  Making memory
 * executable at runtime is a prerequisite for every in-process code-injection
 * attack (shellcode, JIT engine abuse, GOT overwrite + exec).
 */
#ifndef PROT_EXEC
# define PROT_EXEC 0x4
#endif
#define DENY_IF_PROT_EXEC(syscallnr)  DENY_IF_FLAG_SET((syscallnr), 2, PROT_EXEC)

/*
 * DENY_IF_CLONE_NS(syscallnr) — kill if any namespace-creation flag is set
 * in the flags argument (args[0]) of clone(2).
 *
 * The shim needs clone/fork to restart the ircd, but has no reason to create
 * new namespaces.  Blocking CLONE_NEW* flags prevents a compromised shim from
 * using clone to build a fresh namespace for privilege escalation or evasion.
 *
 * clone3(2) passes flags inside a struct pointer (not directly in args[0])
 * and cannot be safely filtered here; it is allowed as-is for lockdown_shim
 * (glibc's fork() uses clone3 on modern kernels with only SIGCHLD-related
 * flags, never namespace flags).
 */
#ifndef CLONE_NEWTIME
# define CLONE_NEWTIME   0x00000080U
#endif
#ifndef CLONE_NEWNS
# define CLONE_NEWNS     0x00020000U
#endif
#ifndef CLONE_NEWCGROUP
# define CLONE_NEWCGROUP 0x02000000U
#endif
#ifndef CLONE_NEWUTS
# define CLONE_NEWUTS    0x04000000U
#endif
#ifndef CLONE_NEWIPC
# define CLONE_NEWIPC    0x08000000U
#endif
#ifndef CLONE_NEWUSER
# define CLONE_NEWUSER   0x10000000U
#endif
#ifndef CLONE_NEWPID
# define CLONE_NEWPID    0x20000000U
#endif
#ifndef CLONE_NEWNET
# define CLONE_NEWNET    0x40000000U
#endif
#define CLONE_NAMESPACE_MASK \
    (CLONE_NEWTIME | CLONE_NEWNS  | CLONE_NEWCGROUP | CLONE_NEWUTS | \
     CLONE_NEWIPC  | CLONE_NEWUSER | CLONE_NEWPID   | CLONE_NEWNET)
#define DENY_IF_CLONE_NS(syscallnr) \
    DENY_IF_FLAG_SET((syscallnr), 0, CLONE_NAMESPACE_MASK)

int
op_seccomp_lockdown(void)
{
    struct sock_filter filter[] = {

#ifdef SECCOMP_AUDIT_ARCH
        /*
         * Architecture guard — load the arch field and kill the process
         * if it does not match our expected ABI.  This prevents a 32-bit
         * payload from using a different syscall table to bypass the
         * deny-list below.
         *
         *   BPF_JEQ jt=1 jf=0: if arch matches → skip KILL, else → KILL.
         */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif /* SECCOMP_AUDIT_ARCH */

        /* Load the syscall number into the accumulator. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr)),

        /* ── exec ───────────────────────────────────────────────────── */
#ifdef __NR_execve
        DENY_SYSCALL(__NR_execve),
#endif
#ifdef __NR_execveat
        DENY_SYSCALL(__NR_execveat),
#endif

        /* ── fork / process creation ────────────────────────────────── */
#ifdef __NR_fork
        DENY_SYSCALL(__NR_fork),
#endif
#ifdef __NR_vfork
        DENY_SYSCALL(__NR_vfork),
#endif
#ifdef __NR_clone
        DENY_SYSCALL(__NR_clone),
#endif
#ifdef __NR_clone3
        DENY_SYSCALL(__NR_clone3),
#endif

        /* ── debugging / cross-process memory access ────────────────── */
#ifdef __NR_ptrace
        DENY_SYSCALL(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
        DENY_SYSCALL(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
        DENY_SYSCALL(__NR_process_vm_writev),
#endif

        /* ── kernel replacement ─────────────────────────────────────── */
#ifdef __NR_kexec_load
        DENY_SYSCALL(__NR_kexec_load),
#endif
#ifdef __NR_kexec_file_load
        DENY_SYSCALL(__NR_kexec_file_load),
#endif

        /* ── eBPF — loading new programs can escape the sandbox ─────── */
#ifdef __NR_bpf
        DENY_SYSCALL(__NR_bpf),
#endif

        /* ── kernel keyring ─────────────────────────────────────────── */
#ifdef __NR_keyctl
        DENY_SYSCALL(__NR_keyctl),
#endif
#ifdef __NR_add_key
        DENY_SYSCALL(__NR_add_key),
#endif
#ifdef __NR_request_key
        DENY_SYSCALL(__NR_request_key),
#endif

        /* ── namespace manipulation ─────────────────────────────────── */
#ifdef __NR_unshare
        DENY_SYSCALL(__NR_unshare),
#endif
#ifdef __NR_setns
        DENY_SYSCALL(__NR_setns),
#endif
#ifdef __NR_pivot_root
        DENY_SYSCALL(__NR_pivot_root),
#endif

        /* ── performance monitoring (can leak kernel addresses) ─────── */
#ifdef __NR_perf_event_open
        DENY_SYSCALL(__NR_perf_event_open),
#endif

        /* ── io_uring: NOT denied — child ircd processes inherit this filter
         *    and use io_uring as their I/O backend.  Denying these syscalls
         *    causes the new ircd to receive SIGSYS immediately on startup,
         *    breaking /UPGRADE and crash-restart. ─────────────────────── */

        /* ── userfaultfd (TOCTOU / memory-inspection gadget) ──────── */
#ifdef __NR_userfaultfd
        DENY_SYSCALL(__NR_userfaultfd),
#endif

        /* ── x86 LDT manipulation (legacy 32-bit segment descriptor
         *    write; no modern daemon needs this; used in past exploits) */
#ifdef __NR_modify_ldt
        DENY_SYSCALL(__NR_modify_ldt),
#endif

        /* ── Obsolete / never-needed kernel interfaces ──────────────── */
#ifdef __NR_nfsservctl
        DENY_SYSCALL(__NR_nfsservctl),
#endif

        /* ── Kernel module loading (instant root if exploited) ──────── */
#ifdef __NR_init_module
        DENY_SYSCALL(__NR_init_module),
#endif
#ifdef __NR_finit_module
        DENY_SYSCALL(__NR_finit_module),
#endif
#ifdef __NR_delete_module
        DENY_SYSCALL(__NR_delete_module),
#endif

        /* ── Filesystem root change — no daemon should ever chroot ──── */
#ifdef __NR_chroot
        DENY_SYSCALL(__NR_chroot),
#endif

        /* ── x86 I/O port access (ring-0 equivalent on some CPUs) ───── */
#ifdef __NR_iopl
        DENY_SYSCALL(__NR_iopl),
#endif
#ifdef __NR_ioperm
        DENY_SYSCALL(__NR_ioperm),
#endif

        /* ── SysV shared memory — no daemon needs IPC shm ───────────── *
         *
         * shmat(shmid, shmaddr, SHM_EXEC) maps shared memory as
         * executable, bypassing the DENY_IF_PROT_EXEC check below.
         * Denying the entire SysV IPC shm family is safe: daemons use
         * op_secure_alloc (anonymous mmap) not SysV IPC.              */
#ifdef __NR_shmget
        DENY_SYSCALL(__NR_shmget),
#endif
#ifdef __NR_shmat
        DENY_SYSCALL(__NR_shmat),
#endif
#ifdef __NR_shmctl
        DENY_SYSCALL(__NR_shmctl),
#endif

        /* ── Process accounting — no daemon needs this ───────────────── */
#ifdef __NR_acct
        DENY_SYSCALL(__NR_acct),
#endif

        /* ── Kernel log buffer — daemons use libc syslog(3), not this── */
#ifdef __NR_syslog
        DENY_SYSCALL(__NR_syslog),
#endif

        /* ── ASLR disable — personality(PER_LINUX_32BIT / READ_IMPLIES_EXEC
         *    etc.) can turn off address-space randomisation, eliminating the
         *    entropy that makes ASLR-dependent exploit mitigations effective. */
#ifdef __NR_personality
        DENY_SYSCALL(__NR_personality),
#endif

        /* ── vmsplice / splice / tee — zero-copy pipe operations ────────── *
         *
         * vmsplice(2) transfers pages from userspace directly to a pipe's
         * page-cache, bypassing the normal copy path.  An attacker with
         * arbitrary write can use it to inject data into kernel pipe buffers.
         * splice(2) and tee(2) are the FD-to-FD variants; none are needed
         * by short-lived helper daemons after initialisation.              */
#ifdef __NR_vmsplice
        DENY_SYSCALL(__NR_vmsplice),
#endif
#ifdef __NR_splice
        DENY_SYSCALL(__NR_splice),
#endif
#ifdef __NR_tee
        DENY_SYSCALL(__NR_tee),
#endif

        /* ── Filesystem mounting — helpers never mount filesystems ──────── */
#ifdef __NR_mount
        DENY_SYSCALL(__NR_mount),
#endif
#ifdef __NR_umount2
        DENY_SYSCALL(__NR_umount2),
#endif

        /* ── Anonymous executable files — W^X belt-and-suspenders ──────── *
         *
         * memfd_create(2) creates an anonymous file backed by RAM.  Combined
         * with write() + fexecve() (or mmap(PROT_EXEC) on the fd) it provides
         * an in-memory execution path that bypasses the mmap/mprotect filter.
         * Helpers never need anonymous tmpfiles; all their I/O uses sockets
         * or pre-opened file descriptors.                                   */
#ifdef __NR_memfd_create
        DENY_SYSCALL(__NR_memfd_create),
#endif

        /* ── copy_file_range — kernel-side FD-to-FD copy not needed ─────── */
#ifdef __NR_copy_file_range
        DENY_SYSCALL(__NR_copy_file_range),
#endif

        /* ── File-handle-based open — bypasses normal VFS path checks ───── *
         *
         * name_to_handle_at(2) + open_by_handle_at(2) allow re-opening a
         * file by an opaque kernel handle, potentially bypassing chroot,
         * bind-mount, and O_PATH restrictions.  No daemon needs these.      */
#ifdef __NR_name_to_handle_at
        DENY_SYSCALL(__NR_name_to_handle_at),
#endif
#ifdef __NR_open_by_handle_at
        DENY_SYSCALL(__NR_open_by_handle_at),
#endif

        /* ── Landlock — nested userspace filesystem sandbox ─────────────── *
         *
         * Landlock (Linux ≥ 5.13) lets unprivileged processes impose their
         * own filesystem restrictions.  A compromised helper could install a
         * Landlock ruleset to restrict its own descendants in unexpected ways.
         * Helpers have no legitimate use for this.                          */
#ifdef __NR_landlock_create_ruleset
        DENY_SYSCALL(__NR_landlock_create_ruleset),
#endif
#ifdef __NR_landlock_add_rule
        DENY_SYSCALL(__NR_landlock_add_rule),
#endif
#ifdef __NR_landlock_restrict_self
        DENY_SYSCALL(__NR_landlock_restrict_self),
#endif

        /* ── membarrier — cross-process memory barrier / DoS vector ─────── *
         *
         * membarrier(MEMBARRIER_CMD_GLOBAL) issues an IPI to every CPU,
         * serialising all running threads.  An exploited helper can use this
         * as a low-noise DoS primitive.  Helpers are single-threaded and have
         * no use for cross-process barriers.                                 */
#ifdef __NR_membarrier
        DENY_SYSCALL(__NR_membarrier),
#endif

        /* ── seccomp — prevent installing additional filters ────────────── *
         *
         * After this filter is installed, any further seccomp(2) call from
         * the helper is unnecessary.  New filters can only be stricter
         * (stacking is one-way), but denying the syscall entirely removes
         * one more post-exploitation tool.  Safe for helpers that call
         * op_seccomp_lockdown() once at startup and never again.
         *
         * NOT added to op_seccomp_lockdown_shim(): the ircd child inherits
         * the shim's filter and must be able to call op_seccomp_lockdown()
         * to install its own filter after startup.                          */
#ifdef __NR_seccomp
        DENY_SYSCALL(__NR_seccomp),
#endif

        /* ── Process file descriptors — FD theft / signal injection ─────── *
         *
         * pidfd_open(2) opens a persistent handle to an arbitrary process.
         * pidfd_getfd(2) then clones any FD from that process into the caller
         * — a direct FD-theft primitive that bypasses normal access controls.
         * pidfd_send_signal(2) delivers signals via pidfd, crossing process-
         * group boundaries.  None are needed by helper daemons.              */
#ifdef __NR_pidfd_open
        DENY_SYSCALL(__NR_pidfd_open),
#endif
#ifdef __NR_pidfd_getfd
        DENY_SYSCALL(__NR_pidfd_getfd),
#endif
#ifdef __NR_pidfd_send_signal
        DENY_SYSCALL(__NR_pidfd_send_signal),
#endif

        /* ── Cross-process memory interference ──────────────────────────── *
         *
         * process_madvise(2) (Linux ≥ 5.10) applies madvise hints to another
         * process's address space.  MADV_DONTNEED on a victim's stack silently
         * zeroes those pages on next access, crashing the target.  Helpers
         * never advise another process's memory.                             */
#ifdef __NR_process_madvise
        DENY_SYSCALL(__NR_process_madvise),
#endif

        /* ── Cross-process comparison — information leakage ─────────────── *
         *
         * kcmp(2) compares kernel objects (FDs, file descriptions, VM areas)
         * across process boundaries, revealing layout details of other
         * processes' internal state.  No daemon needs this.                  */
#ifdef __NR_kcmp
        DENY_SYSCALL(__NR_kcmp),
#endif

        /* ── Real-time scheduling — CPU starvation DoS ───────────────────── *
         *
         * sched_setscheduler(2) and sched_setattr(2) can request SCHED_FIFO /
         * SCHED_RR priority, monopolising a CPU core.  CAP_SYS_NICE would be
         * required for RT classes, which helpers do not hold, but denying the
         * calls entirely removes the option.  Helpers never change scheduling
         * class after initialisation.                                         */
#ifdef __NR_sched_setscheduler
        DENY_SYSCALL(__NR_sched_setscheduler),
#endif
#ifdef __NR_sched_setattr
        DENY_SYSCALL(__NR_sched_setattr),
#endif

        /* ── New VFS mount API (Linux ≥ 5.2) — filesystem mounting ──────── *
         *
         * open_tree(2), move_mount(2), fsopen(2), fsconfig(2), fsmount(2),
         * fspick(2), and open_tree_attr(2) (Linux ≥ 6.15) are the modern
         * replacements for mount(2).  Since mount(2) is already denied above,
         * these must be denied too or an attacker could mount filesystems
         * through the new interface.  Daemons have no legitimate use for
         * any filesystem mounting after initialisation.                       */
#ifdef __NR_open_tree
        DENY_SYSCALL(__NR_open_tree),
#endif
#ifdef __NR_move_mount
        DENY_SYSCALL(__NR_move_mount),
#endif
#ifdef __NR_fsopen
        DENY_SYSCALL(__NR_fsopen),
#endif
#ifdef __NR_fsconfig
        DENY_SYSCALL(__NR_fsconfig),
#endif
#ifdef __NR_fsmount
        DENY_SYSCALL(__NR_fsmount),
#endif
#ifdef __NR_fspick
        DENY_SYSCALL(__NR_fspick),
#endif
#ifdef __NR_open_tree_attr
        DENY_SYSCALL(__NR_open_tree_attr),
#endif

        /* ── Memory sealing (Linux ≥ 6.10) ──────────────────────────────── *
         *
         * mseal(2) locks a VMA's protections and address range so that
         * subsequent mprotect / munmap calls on it fail with EPERM.
         * A compromised daemon could use it to pin malicious executable
         * mappings in place, preventing any post-exploitation cleanup or
         * W^X enforcement from unmapping them.  Daemons never need to seal
         * their own mappings.                                                */
#ifdef __NR_mseal
        DENY_SYSCALL(__NR_mseal),
#endif

        /* ── W^X enforcement: deny making memory executable ─────────── *
         *
         * Covers mmap(2), mprotect(2), and pkey_mprotect(2) — all place
         * the prot argument at args[2].  DENY_IF_PROT_EXEC generates 7
         * BPF instructions per syscall: kills only when PROT_EXEC is set
         * in the prot argument; all benign calls fall through.
         *
         * shmat(SHM_EXEC) is a separate W^X bypass path; it is blocked
         * above by denying the entire shmat syscall.
         * memfd_create + fexecve is blocked above by denying memfd_create. */
#ifdef __NR_mprotect
        DENY_IF_PROT_EXEC(__NR_mprotect),
#endif
#ifdef __NR_mmap
        DENY_IF_PROT_EXEC(__NR_mmap),
#endif
#ifdef __NR_pkey_mprotect
        DENY_IF_PROT_EXEC(__NR_pkey_mprotect),
#endif

        /* Allow everything else. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    /*
     * PR_SET_NO_NEW_PRIVS: prevent any setuid/setgid escalation after
     * this point.  Required before installing a seccomp filter when the
     * process doesn't hold CAP_SYS_ADMIN.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;

    return install_seccomp_filter(&prog);
}

/*
 * op_seccomp_lockdown_shim — shim-appropriate BPF filter.
 *
 * Same denylist as op_seccomp_lockdown() MINUS the fork/exec/clone denials
 * (the shim must be able to launch and restart the ircd binary).
 *
 * NOTE: socket(2), connect(2), and mmap/mprotect PROT_EXEC are intentionally
 * NOT restricted in this filter.  This filter is inherited by the ircd child
 * across fork+exec.  The ircd needs AF_INET/AF_INET6 sockets and connect(2)
 * for outbound S2S links, auth, and resolver, and ld.so needs mmap(PROT_EXEC)
 * to map shared library text segments before main() runs.  Seccomp filters can
 * only be tightened by a child process, never relaxed; the ircd installs its
 * own op_seccomp_lockdown() filter after startup which applies all of these
 * restrictions in the context of a fully-initialised process.
 */
int
op_seccomp_lockdown_shim(void)
{
    struct sock_filter filter[] = {

#ifdef SECCOMP_AUDIT_ARCH
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (unsigned int)offsetof(struct seccomp_data, nr)),

        /* ── socket / connect: intentionally NOT restricted here ───────────
         *
         * This filter is inherited by ircd child processes across fork+exec.
         * The ircd needs AF_INET / AF_INET6 sockets for listener handoff,
         * outbound server links, auth connections, and resolver sockets.
         * It also needs connect(2) for outbound server-to-server links.
         *
         * The shim itself only creates AF_UNIX sockets, but we cannot apply
         * a domain restriction without also blocking the ircd child.
         * Seccomp filters stack one-way: a child can only add stricter rules.
         * The ircd installs its own op_seccomp_lockdown() filter after startup.
         * ────────────────────────────────────────────────────────────────── */

        /* ── debugging / cross-process memory access (highest priority) ─── */
#ifdef __NR_ptrace
        DENY_SYSCALL(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
        DENY_SYSCALL(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
        DENY_SYSCALL(__NR_process_vm_writev),
#endif

        /* ── kernel replacement ─────────────────────────────────────────── */
#ifdef __NR_kexec_load
        DENY_SYSCALL(__NR_kexec_load),
#endif
#ifdef __NR_kexec_file_load
        DENY_SYSCALL(__NR_kexec_file_load),
#endif

        /* ── eBPF ───────────────────────────────────────────────────────── */
#ifdef __NR_bpf
        DENY_SYSCALL(__NR_bpf),
#endif

        /* ── kernel keyring ─────────────────────────────────────────────── */
#ifdef __NR_keyctl
        DENY_SYSCALL(__NR_keyctl),
#endif
#ifdef __NR_add_key
        DENY_SYSCALL(__NR_add_key),
#endif
#ifdef __NR_request_key
        DENY_SYSCALL(__NR_request_key),
#endif

        /* ── namespace manipulation ─────────────────────────────────────── */
#ifdef __NR_unshare
        DENY_SYSCALL(__NR_unshare),
#endif
#ifdef __NR_setns
        DENY_SYSCALL(__NR_setns),
#endif
#ifdef __NR_pivot_root
        DENY_SYSCALL(__NR_pivot_root),
#endif

        /* ── performance monitoring ─────────────────────────────────────── */
#ifdef __NR_perf_event_open
        DENY_SYSCALL(__NR_perf_event_open),
#endif

        /* ── io_uring: intentionally NOT denied here ────────────────────── *
         *
         * The ircd child inherits this filter and uses io_uring as its sole
         * I/O backend (io_uring_setup on startup; io_uring_enter / _register
         * throughout the run).  Denying these causes the new ircd to receive
         * SIGSYS before it can send HELLO to the shim, breaking both /UPGRADE
         * and crash-restart.
         * ────────────────────────────────────────────────────────────────── */

        /* ── userfaultfd ────────────────────────────────────────────────── */
#ifdef __NR_userfaultfd
        DENY_SYSCALL(__NR_userfaultfd),
#endif

        /* ── x86 LDT ────────────────────────────────────────────────────── */
#ifdef __NR_modify_ldt
        DENY_SYSCALL(__NR_modify_ldt),
#endif

        /* ── Obsolete kernel interfaces ──────────────────────────────────── */
#ifdef __NR_nfsservctl
        DENY_SYSCALL(__NR_nfsservctl),
#endif

        /* ── Kernel module loading ────────────────────────────────────────── */
#ifdef __NR_init_module
        DENY_SYSCALL(__NR_init_module),
#endif
#ifdef __NR_finit_module
        DENY_SYSCALL(__NR_finit_module),
#endif
#ifdef __NR_delete_module
        DENY_SYSCALL(__NR_delete_module),
#endif

        /* ── Filesystem root change ───────────────────────────────────────── */
#ifdef __NR_chroot
        DENY_SYSCALL(__NR_chroot),
#endif

        /* ── x86 I/O port access (ring-0 equivalent) ─────────────────────── */
#ifdef __NR_iopl
        DENY_SYSCALL(__NR_iopl),
#endif
#ifdef __NR_ioperm
        DENY_SYSCALL(__NR_ioperm),
#endif

        /* ── SysV shared memory (shmat(SHM_EXEC) bypasses W^X) ───────────── *
         *
         * shmat(shmid, shmaddr, SHM_EXEC) maps shared memory with execute
         * permission, providing a W^X bypass path not covered by the mmap /
         * mprotect argument filters below.  Denying the entire SysV IPC shm
         * family is safe: daemons use op_secure_alloc (anonymous mmap) not
         * SysV IPC.                                                           */
#ifdef __NR_shmget
        DENY_SYSCALL(__NR_shmget),
#endif
#ifdef __NR_shmat
        DENY_SYSCALL(__NR_shmat),
#endif
#ifdef __NR_shmctl
        DENY_SYSCALL(__NR_shmctl),
#endif

        /* ── Process accounting ───────────────────────────────────────────── */
#ifdef __NR_acct
        DENY_SYSCALL(__NR_acct),
#endif

        /* ── Kernel log buffer (daemons use libc syslog(3) via /dev/log) ──── */
#ifdef __NR_syslog
        DENY_SYSCALL(__NR_syslog),
#endif

        /* ── ASLR disable ────────────────────────────────────────────────── */
#ifdef __NR_personality
        DENY_SYSCALL(__NR_personality),
#endif

        /* ── vmsplice — user-to-pipe page-cache write ────────────────────── *
         *
         * vmsplice transfers userspace pages directly into a pipe's page cache.
         * Unlike splice/tee (which the ircd child may legitimately use for
         * zero-copy I/O), vmsplice is a pure attack primitive for a sandboxed
         * process and is never needed by the shim.  splice and tee are omitted
         * here: the ircd inherits this filter and may use them for non-TLS
         * data paths (log rotation, auth pipe).                              */
#ifdef __NR_vmsplice
        DENY_SYSCALL(__NR_vmsplice),
#endif

        /* ── Filesystem mounting ─────────────────────────────────────────── */
#ifdef __NR_mount
        DENY_SYSCALL(__NR_mount),
#endif
#ifdef __NR_umount2
        DENY_SYSCALL(__NR_umount2),
#endif

        /* ── File-handle-based open (VFS path bypass) ────────────────────── */
#ifdef __NR_name_to_handle_at
        DENY_SYSCALL(__NR_name_to_handle_at),
#endif
#ifdef __NR_open_by_handle_at
        DENY_SYSCALL(__NR_open_by_handle_at),
#endif

        /* ── Landlock nested sandbox ─────────────────────────────────────── */
#ifdef __NR_landlock_create_ruleset
        DENY_SYSCALL(__NR_landlock_create_ruleset),
#endif
#ifdef __NR_landlock_add_rule
        DENY_SYSCALL(__NR_landlock_add_rule),
#endif
#ifdef __NR_landlock_restrict_self
        DENY_SYSCALL(__NR_landlock_restrict_self),
#endif

        /* ── membarrier — cross-process IPI / DoS vector ─────────────────── */
#ifdef __NR_membarrier
        DENY_SYSCALL(__NR_membarrier),
#endif

        /* ── Process file descriptors — FD theft / signal injection ─────── *
         *
         * pidfd_getfd(2) clones an FD out of another process — a direct theft
         * primitive.  pidfd_send_signal(2) sends signals cross-group via pidfd.
         * Neither the shim nor the ircd (which inherits this filter) needs
         * these.
         *
         * NOTE: pidfd_open(2) is intentionally NOT denied here.  The shim
         * calls syscall(__NR_pidfd_open, child_pid, 0) in launch_core() to
         * obtain a zero-latency death-detection fd for the ircd child.      */
#ifdef __NR_pidfd_getfd
        DENY_SYSCALL(__NR_pidfd_getfd),
#endif
#ifdef __NR_pidfd_send_signal
        DENY_SYSCALL(__NR_pidfd_send_signal),
#endif

        /* ── Cross-process memory interference ──────────────────────────── */
#ifdef __NR_process_madvise
        DENY_SYSCALL(__NR_process_madvise),
#endif

        /* ── Cross-process comparison — information leakage ─────────────── */
#ifdef __NR_kcmp
        DENY_SYSCALL(__NR_kcmp),
#endif

        /* ── Real-time scheduling — CPU starvation DoS ───────────────────── *
         *
         * Neither the shim nor the ircd child (which inherits this filter)
         * needs SCHED_FIFO / SCHED_RR.  Denying these removes the RT
         * monopolisation vector.                                             */
#ifdef __NR_sched_setscheduler
        DENY_SYSCALL(__NR_sched_setscheduler),
#endif
#ifdef __NR_sched_setattr
        DENY_SYSCALL(__NR_sched_setattr),
#endif

        /* ── Kernel-side file copy — not needed by shim or ircd ─────────── */
#ifdef __NR_copy_file_range
        DENY_SYSCALL(__NR_copy_file_range),
#endif

        /* ── Anonymous executable files — W^X belt-and-suspenders ──────── *
         *
         * Even though DENY_IF_PROT_EXEC cannot be applied in this filter
         * (ld.so needs PROT_EXEC after execve), denying memfd_create removes
         * one in-memory execution path: an attacker cannot write shellcode to
         * an anonymous memfd and mmap it PROT_EXEC without this syscall.    */
#ifdef __NR_memfd_create
        DENY_SYSCALL(__NR_memfd_create),
#endif

        /* ── New VFS mount API (Linux ≥ 5.2) — filesystem mounting ──────── *
         *
         * Mirrors the lockdown filter.  mount(2) is already denied; deny the
         * modern equivalents too so neither shim nor ircd child can mount
         * filesystems through the new interface.                             */
#ifdef __NR_open_tree
        DENY_SYSCALL(__NR_open_tree),
#endif
#ifdef __NR_move_mount
        DENY_SYSCALL(__NR_move_mount),
#endif
#ifdef __NR_fsopen
        DENY_SYSCALL(__NR_fsopen),
#endif
#ifdef __NR_fsconfig
        DENY_SYSCALL(__NR_fsconfig),
#endif
#ifdef __NR_fsmount
        DENY_SYSCALL(__NR_fsmount),
#endif
#ifdef __NR_fspick
        DENY_SYSCALL(__NR_fspick),
#endif
#ifdef __NR_open_tree_attr
        DENY_SYSCALL(__NR_open_tree_attr),
#endif

        /* ── Memory sealing (Linux ≥ 6.10) ──────────────────────────────── *
         *
         * Mirrors the lockdown filter.  Neither the shim nor the ircd child
         * needs mseal(2).                                                    */
#ifdef __NR_mseal
        DENY_SYSCALL(__NR_mseal),
#endif

        /*
         * NOTE: __NR_seccomp is intentionally NOT denied here.
         *
         * This filter is inherited by the ircd child across fork+execve.
         * The ircd calls op_seccomp_lockdown() on startup which issues
         * syscall(__NR_seccomp, ...) to install its own filter.  Denying
         * seccomp here would silently prevent the ircd from sandboxing itself.
         *
         * The ircd's lockdown filter DOES deny __NR_seccomp, so re-filtering
         * after that point is blocked in the ircd process.
         */

        /* ── clone namespace guard ────────────────────────────────────────── *
         *
         * The shim must fork (clone with SIGCHLD) but never needs to create
         * a new namespace.  DENY_IF_CLONE_NS kills clone(2) if any CLONE_NEW*
         * bit is set in flags (args[0]).  clone3(2) cannot be filtered by BPF
         * flag inspection (it embeds flags in a struct pointer); it is allowed
         * as-is — glibc fork() only sets SIGCHLD-related flags in clone3.   */
#ifdef __NR_clone
        DENY_IF_CLONE_NS(__NR_clone),
#endif

        /* ── W^X (mmap/mprotect PROT_EXEC): intentionally NOT denied here ─ *
         *
         * DENY_IF_PROT_EXEC cannot safely appear in the shim filter because
         * this filter is inherited across fork+exec by the new ircd child.
         * The ircd's dynamic linker (ld.so) calls mmap(PROT_READ|PROT_EXEC)
         * to map text segments of shared libraries immediately after execve,
         * before main() runs.  Denying PROT_EXEC here would kill ld.so and
         * prevent the new ircd from starting at all.
         *
         * Additionally, the ircd loads modules at runtime via dlopen(3),
         * which also calls mmap/mprotect with PROT_EXEC.
         *
         * The ircd installs its own op_seccomp_lockdown() filter after startup
         * completion; that filter applies W^X and all other restrictions in the
         * context of the fully-initialised ircd process.
         * ────────────────────────────────────────────────────────────────── */

        /* fork/execve/clone are intentionally NOT denied — the shim needs them. */

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;

    return install_seccomp_filter(&prog);
}

/* ── Process hardening ────────────────────────────────────────────────────── */

/*
 * op_shim_harden — early process-level hardening for the shim.
 *
 * Call at the very start of main(), before binding listeners or launching
 * any child process.
 *
 * Three measures are applied:
 *
 *   PR_SET_DUMPABLE 0 — Disable core dump generation.  The shim buffers
 *   live TLS session key blobs during /UPGRADE.  Without this, a crash
 *   at that moment writes every session key to disk in plaintext.
 *   PR_SET_DUMPABLE 0 also prevents /proc/PID/mem writes by other processes
 *   (including root on kernels with CONFIG_SECURITY_YAMA=y, ptrace_scope≥1).
 *
 *   RLIMIT_CORE = 0 — Belt-and-suspenders for the above; prevents core files
 *   even if PR_SET_DUMPABLE is reset by a child exec that restores dumpable
 *   status (e.g. a setuid/setgid binary).
 *
 *   PR_SET_CHILD_SUBREAPER 1 — Make the shim the reaping ancestor of its
 *   entire process subtree.  If the ircd spawns grandchildren (e.g. the
 *   authproc curl/wget download fork) and then dies before they exit, those
 *   orphans are reparented to the shim rather than to PID 1.  The shim's
 *   main loop already calls waitpid(); with subreaper set it will properly
 *   reap these orphans rather than leaving zombies for systemd.
 *
 * Returns 0 if all three measures succeeded, -1 if any failed (errno set
 * to the failure from the last failing call).  Partial success is still
 * useful — apply regardless.
 */
int
op_shim_harden(void)
{
    int ok = 1;

    /* No core dumps while session key blobs may be in memory. */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        ok = 0;

    /* Belt-and-suspenders: hard RLIMIT_CORE = 0. */
#ifdef HAVE_SYS_RESOURCE_H
    {
        struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
        if (setrlimit(RLIMIT_CORE, &rl) < 0)
            ok = 0;
    }
#endif

    /* Become subreaper — orphaned ircd grandchildren reparent here. */
#ifdef PR_SET_CHILD_SUBREAPER
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
        ok = 0;
#endif

    /*
     * PR_SET_NO_NEW_PRIVS — prevent privilege escalation via setuid/setgid
     * exec after this point.  This is also set inside op_seccomp_lockdown_shim()
     * as a seccomp prerequisite, but setting it here (before the filter is
     * installed) ensures it is in effect even if lockdown fails entirely on
     * older kernels.  Belt-and-suspenders: the flag is idempotent.
     *
     * This is the single most impactful per-process hardening measure:
     * it prevents any future exec() from acquiring elevated privileges through
     * setuid/setgid binaries or filesystem capabilities, even if an attacker
     * succeeds in hijacking the exec path.
     */
#ifdef PR_SET_NO_NEW_PRIVS
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        ok = 0;
#endif

    return ok ? 0 : -1;
}

/* ── Secure memory ────────────────────────────────────────────────────────── */

/*
 * PR_SET_VMA / PR_SET_VMA_ANON_NAME — annotate anonymous mappings with a
 * name visible in /proc/PID/maps (Linux ≥ 5.17).  Allows security auditing
 * tools and operators to identify secure regions at a glance.
 */
#ifndef PR_SET_VMA
# define PR_SET_VMA           0x53564d41   /* "SVMA" */
# define PR_SET_VMA_ANON_NAME 0
#endif

/*
 * op_secure_page_size — cached page size for guard-page arithmetic.
 * sysconf(_SC_PAGESIZE) is called once; the result never changes.
 */
static size_t
op_secure_page_size(void)
{
    static size_t _page = 0;
    if (_page == 0) {
        long r = sysconf(_SC_PAGESIZE);
        _page = (r > 0) ? (size_t)r : 4096u;
    }
    return _page;
}

/*
 * op_secure_alloc — kernel-isolated secret memory with layered protection.
 *
 * Allocation strategy (strongest to weakest):
 *
 *   1. memfd_secret(2) — Linux ≥ 5.14.  Kernel-isolated mapping invisible to
 *      /proc/PID/mem and inaccessible via ptrace even as root.  PKS-enforced
 *      on x86 where available.  fd closed after mmap; mapping persists.
 *
 *   2. MAP_PRIVATE|MAP_ANONYMOUS + MADV_WIPEONFORK — Linux ≥ 4.14.  Any
 *      fork()ed child sees zeroed pages; TLS keys never reach ircd children.
 *      MADV_DONTDUMP excludes the region from core dumps on fallback kernels.
 *
 * All successful allocations additionally receive:
 *   • Guard pages: one PROT_NONE page is placed immediately before and
 *     after the usable region.  Any buffer overflow or underflow in session
 *     blob parsing causes an immediate SIGSEGV rather than silent corruption
 *     of an adjacent client's session keys.
 *   • mlock() — pin the data pages in RAM; prevents session keys reaching swap.
 *     Best-effort: silently ignored if RLIMIT_MEMLOCK is exhausted.
 *   • PR_SET_VMA_ANON_NAME "ophion-secure" — labels the data pages as
 *     [anon:ophion-secure] in /proc/PID/maps so security auditing tools can
 *     identify them (Linux ≥ 5.17; silently no-op on older kernels).
 *
 * Returns a pointer to the usable (PROT_READ|PROT_WRITE) region on success,
 * NULL on failure.  The region is zeroed on first use.
 */
void *
op_secure_alloc(size_t len)
{
    if (len == 0)
        return NULL;

    size_t page   = op_secure_page_size();

    /* Overflow check: len_pg = round_up(len, page); total = 3 * page + len_pg.
     * If len > SIZE_MAX - 2*page, the additions below would wrap. */
    if (len > SIZE_MAX - (2 * page))
        return NULL;

    /* Round len up to a page boundary so the trailing guard starts aligned. */
    size_t len_pg = (len + page - 1) & ~(page - 1);
    size_t total  = page + len_pg + page;   /* [guard][data][guard] */

    void *base = MAP_FAILED;

    /* ── Strategy 1: memfd_secret (Linux ≥ 5.14) ────────────────────────── */
#ifdef __NR_memfd_secret
    {
        int fd = (int)syscall(__NR_memfd_secret, 0U);
        if (fd >= 0) {
            if (ftruncate(fd, (off_t)total) == 0) {
                base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
            }
            close(fd);
            if (base != MAP_FAILED)
                goto guard;
            base = MAP_FAILED;
        }
    }
#endif

    /* ── Strategy 2: anonymous mmap + MADV_WIPEONFORK + MADV_DONTDUMP ───── */
    base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED)
        return NULL;

    {
        /* Apply isolation hints only to the data region, not the guards. */
        void *data = (uint8_t *)base + page;
#ifdef MADV_WIPEONFORK
        madvise(data, len_pg, MADV_WIPEONFORK);
#endif
#ifdef MADV_DONTDUMP
        madvise(data, len_pg, MADV_DONTDUMP);
#endif
    }

guard:
    /*
     * Arm guard pages.  Both the leading and trailing PROT_NONE pages are
     * part of the same mmap() allocation; mprotect() changes only their
     * access rights, not their identity.  munmap() releases all three
     * regions atomically in op_secure_free().
     *
     * Note: mprotect(PROT_NONE) passes the DENY_IF_PROT_EXEC BPF filter
     * because PROT_NONE = 0x0, and 0 & PROT_EXEC = 0.
     */
    mprotect(base, page, PROT_NONE);
    mprotect((uint8_t *)base + page + len_pg, page, PROT_NONE);

    void *p = (uint8_t *)base + page;

    /*
     * Annotate the data region in /proc/PID/maps as [anon:ophion-secure].
     * Security auditing tools (eBPF monitors, process introspection scripts)
     * can now distinguish these regions from ordinary heap allocations.
     * Available on Linux ≥ 5.17; silently ignored (EINVAL) on older kernels.
     */
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
          (unsigned long)p, len_pg, (unsigned long)"ophion-secure");

    mlock(p, len);   /* pin data pages in RAM — best-effort */
    return p;
}

/*
 * op_secure_free — explicit_bzero + munmap (guard-page aware).
 *
 * Computes the allocation base (p − one page) and total size
 * (page + round_up(len) + page) identically to op_secure_alloc(), then:
 *   1. explicit_bzero(p, len) — overwrites only the usable data region
 *      (the guard pages are PROT_NONE and must not be touched).
 *   2. munmap(base, total) — releases the entire three-region allocation.
 */
void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0)
        return;

    size_t page   = op_secure_page_size();
    size_t len_pg = (len + page - 1) & ~(page - 1);

    explicit_bzero(p, len);   /* wipe only the usable region */

    void *base = (uint8_t *)p - page;
    munmap(base, page + len_pg + page);
}

/* ============================================================
 * OpenBSD — pledge() + unveil() sandboxing
 * ============================================================ */
#elif defined(__OpenBSD__)

#include <op_seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>      /* pledge(), unveil(), explicit_bzero */
#include <sys/mman.h>
#include <sys/resource.h>

/*
 * op_seccomp_lockdown — pledge("stdio") for helper daemons.
 *
 * Limits the process to basic I/O syscalls only.  Any attempt to call
 * a syscall outside the stdio promise immediately terminates the process
 * with SIGABRT, logged to the audit trail.
 */
int
op_seccomp_lockdown(void)
{
    return pledge("stdio", NULL) < 0 ? -1 : 0;
}

/*
 * op_seccomp_lockdown_shim — pledge() + unveil() for the shim.
 *
 * Two complementary restrictions:
 *
 *   pledge("stdio proc exec", NULL) — allows basic I/O, fork/wait, and
 *   execve.  Denies all filesystem open/create, network socket creation,
 *   and sysctl.  The shim only needs to exec the ircd binary and manage
 *   already-open file descriptors.
 *
 *   unveil(BINDIR, "rx") + unveil(NULL, NULL) — restricts filesystem
 *   access to the ircd binary directory (read + execute only) and then
 *   locks unveil so no further paths can be added.  Any attempt by an
 *   attacker to exec a different binary is denied at the vfs layer.
 *
 * BINDIR is defined at build time via meson.  If not defined, the unveil
 * restriction is skipped (pledge still applies).
 *
 * unveil() is available on OpenBSD ≥ 6.4.  The __OpenBSD__ guard on the
 * whole section ensures it is never compiled elsewhere.
 */
int
op_seccomp_lockdown_shim(void)
{
#ifdef BINDIR
    /* Restrict filesystem visibility: only the ircd binary directory and
     * /usr/lib (for the dynamic linker when exec'ing the ircd) are exposed. */
    if (unveil(BINDIR, "rx") < 0)    return -1;
    if (unveil("/usr/lib", "r") < 0) return -1;
    if (unveil("/usr/libexec", "r") < 0) return -1;   /* ld.so */
    if (unveil(NULL, NULL) < 0)      return -1;        /* lock */
#endif
    return pledge("stdio proc exec", NULL) < 0 ? -1 : 0;
}

/*
 * op_shim_harden — OpenBSD early hardening.
 *
 * OpenBSD: no PR_SET_DUMPABLE equivalent, but pledge restrictions combined
 * with kern.nosuidcoredump=3 (system-wide default) provide equivalent
 * protection.  We additionally set RLIMIT_CORE = 0 as belt-and-suspenders.
 */
int
op_shim_harden(void)
{
    int ok = 1;
    struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
    if (setrlimit(RLIMIT_CORE, &rl) < 0) ok = 0;
    return ok ? 0 : -1;
}

/*
 * op_secure_alloc — mmap + mlock with guard pages on OpenBSD.
 *
 * Guard pages: one PROT_NONE page before and after the data region.
 * Buffer overflow in session blob parsing causes immediate SIGBUS/SIGSEGV
 * rather than silent corruption.
 *
 * OpenBSD does not have MADV_WIPEONFORK or MADV_DONTDUMP; however, pledge
 * prevents core generation and fork() in the sandboxed shim, so these are
 * not needed after lockdown.
 */
void *
op_secure_alloc(size_t len)
{
    if (len == 0) return NULL;

    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    if (len > (size_t)-1 - (2 * page)) return NULL;   /* overflow guard */
    size_t len_pg = (len + page - 1) & ~(page - 1);
    size_t total  = page + len_pg + page;

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) return NULL;

    /* Arm guard pages. */
    mprotect(base, page, PROT_NONE);
    mprotect((uint8_t *)base + page + len_pg, page, PROT_NONE);

    void *p = (uint8_t *)base + page;
    mlock(p, len);   /* best-effort */
    return p;
}

void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0) return;
    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    size_t len_pg = (len + page - 1) & ~(page - 1);
    explicit_bzero(p, len);
    munmap((uint8_t *)p - page, page + len_pg + page);
}

/* ============================================================
 * FreeBSD / DragonFly BSD — Capsicum + deep process hardening
 * ============================================================ */
#elif defined(__FreeBSD__) || defined(__DragonFly__)

#include <op_seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __FreeBSD__
# include <sys/capsicum.h>
# include <sys/procctl.h>   /* PROC_REAP_ACQUIRE, PROC_TRACELEVEL_CTL */
#endif

/*
 * op_seccomp_lockdown — Capsicum capability mode for helper daemons.
 *
 * cap_enter(2) switches the process into capability mode: all further
 * filesystem namespace operations (open by path, exec by path, etc.)
 * are denied.  Only already-open file descriptors may be used, and only
 * with rights that were explicitly granted at open time.
 *
 * This is a strong, OS-enforced sandbox: an exploited helper daemon
 * cannot open new files, exec new binaries, or create network connections.
 *
 * DragonFly BSD: cap_enter is available but the procctl extensions are not.
 */
int
op_seccomp_lockdown(void)
{
#ifdef __FreeBSD__
    return cap_enter() < 0 ? -1 : 0;
#else
    return 0;   /* DragonFly: no equivalent */
#endif
}

/*
 * op_seccomp_lockdown_shim — shim is a no-op on this platform.
 *
 * Capsicum cap_enter() prohibits execve() by path, so helper daemons can
 * use it but the shim (which must restart the ircd via execve) cannot.
 *
 * Future improvement: store an fd opened on the ircd binary pre-lockdown
 * and use fexecve(fd, ...) from within capability mode.
 */
int op_seccomp_lockdown_shim(void) { return 0; }

/*
 * op_shim_harden — FreeBSD deep process hardening.
 *
 *   RLIMIT_CORE = 0          — belt-and-suspenders no core dumps.
 *   PROC_REAP_ACQUIRE        — become subreaper; orphaned grandchildren
 *                              reparent here rather than to PID 1.
 *   PROC_TRACELEVEL_CTL = 0  — FreeBSD 12.0+: deny ptrace/ktrace of this
 *                              process even by root.  Prevents a compromised
 *                              ircd from reading the shim's session-key blobs
 *                              via ptrace after a session migration is in
 *                              progress.  Silently ignored on older kernels.
 */
int
op_shim_harden(void)
{
    int ok = 1;

    struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
    if (setrlimit(RLIMIT_CORE, &rl) < 0) ok = 0;

#ifdef __FreeBSD__
    if (procctl(P_PID, 0, PROC_REAP_ACQUIRE, NULL) < 0) ok = 0;

# ifdef PROC_TRACELEVEL_CTL
    /*
     * PROC_TRACELEVEL_CTL: 0 = deny all tracing (ptrace/ktrace/procstat).
     * Available since FreeBSD 12.0.  Failure is non-fatal on older releases.
     */
    {
        int trace_level = 0;
        (void)procctl(P_PID, 0, PROC_TRACELEVEL_CTL, &trace_level);
    }
# endif /* PROC_TRACELEVEL_CTL */
#endif /* __FreeBSD__ */

    return ok ? 0 : -1;
}

/*
 * op_secure_alloc — mmap + guard pages + MADV_NOCORE on FreeBSD.
 *
 * MADV_NOCORE (FreeBSD-specific): excludes the region from core dumps
 * even if the process is dumpable.  Combined with guard pages, this
 * gives both overflow protection and dump-exclusion on FreeBSD.
 */
void *
op_secure_alloc(size_t len)
{
    if (len == 0) return NULL;

    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    if (len > (size_t)-1 - (2 * page)) return NULL;   /* overflow guard */
    size_t len_pg = (len + page - 1) & ~(page - 1);
    size_t total  = page + len_pg + page;

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) return NULL;

    void *p = (uint8_t *)base + page;

#ifdef MADV_NOCORE
    /* Exclude data region from core dumps. */
    madvise(p, len_pg, MADV_NOCORE);
#endif

    /* Arm guard pages. */
    mprotect(base, page, PROT_NONE);
    mprotect((uint8_t *)base + page + len_pg, page, PROT_NONE);

    mlock(p, len);   /* pin data pages — best-effort */
    return p;
}

void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0) return;
    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    size_t len_pg = (len + page - 1) & ~(page - 1);
    explicit_bzero(p, len);
    munmap((uint8_t *)p - page, page + len_pg + page);
}

/* ============================================================
 * macOS — process hardening + guard pages
 * ============================================================ */
#elif defined(__APPLE__)

#include <TargetConditionals.h>
#include <op_seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

/*
 * op_seccomp_lockdown — macOS process mitigations.
 *
 * macOS does not have seccomp or pledge.  The available syscall-level
 * restriction mechanism is the App Sandbox (sandbox_init / SBPL profiles),
 * but that requires entitlements and is a compile-time concern.
 *
 * At runtime we apply:
 *   • No-op — no equivalent runtime syscall filter exists on macOS.
 *
 * W^X on Apple Silicon (M1+): the hardware enforces W^X via a per-thread
 * JIT write permission bit.  Ophion never allocates JIT memory, so
 * pthread_jit_write_protect_np() is irrelevant but W^X is inherently
 * enforced by the architecture on these platforms.
 *
 * On macOS 12.0+ (Monterey) the Hardened Runtime entitlement
 * com.apple.security.cs.prevent-library-load prevents loading unsigned
 * libraries; this is a deployment concern, not a runtime measure here.
 */
int op_seccomp_lockdown(void)      { return 0; }
int op_seccomp_lockdown_shim(void) { return 0; }

/*
 * op_shim_harden — macOS process hardening.
 *
 *   RLIMIT_CORE = 0 — prevents core dump generation.  macOS lacks
 *   PR_SET_DUMPABLE; RLIMIT_CORE is the only portable knob.
 *
 *   Note: macOS does not have PR_SET_CHILD_SUBREAPER.  kqueue EVFILT_PROC
 *   NOTE_REAP could be used to watch for orphaned descendants, but this
 *   would require reworking the main event loop.  Orphan reaping on macOS
 *   is left to the default behaviour (re-parented to launchd).
 */
int
op_shim_harden(void)
{
    struct rlimit rl = { .rlim_cur = 0, .rlim_max = 0 };
    return setrlimit(RLIMIT_CORE, &rl) < 0 ? -1 : 0;
}

/*
 * op_secure_alloc — mmap + guard pages + mlock on macOS.
 *
 * macOS does not have MADV_WIPEONFORK or MADV_DONTDUMP.
 * Guard pages and mlock are available on all supported macOS versions.
 * MADV_ZERO_WIRED_PAGES (macOS-specific) zeros mlocked pages when they
 * are eventually unwired — belt-and-suspenders on top of explicit_bzero.
 */
void *
op_secure_alloc(size_t len)
{
    if (len == 0) return NULL;

    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    if (len > (size_t)-1 - (2 * page)) return NULL;   /* overflow guard */
    size_t len_pg = (len + page - 1) & ~(page - 1);
    size_t total  = page + len_pg + page;

    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) return NULL;

    void *p = (uint8_t *)base + page;

#ifdef MADV_ZERO_WIRED_PAGES
    /* Ensure wired pages are zeroed on unwire — supplemental wipe. */
    madvise(p, len_pg, MADV_ZERO_WIRED_PAGES);
#endif

    /* Arm guard pages. */
    mprotect(base, page, PROT_NONE);
    mprotect((uint8_t *)base + page + len_pg, page, PROT_NONE);

    mlock(p, len);   /* pin in RAM — best-effort */
    return p;
}

void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0) return;
    size_t page   = (size_t)sysconf(_SC_PAGESIZE);
    if (!page) page = 4096;
    size_t len_pg = (len + page - 1) & ~(page - 1);
    explicit_bzero(p, len);
    munmap((uint8_t *)p - page, page + len_pg + page);
}

/* ============================================================
 * Windows — comprehensive Win32 process hardening
 * ============================================================ */
#elif defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <op_seccomp.h>
#include <stddef.h>

/*
 * apply_mitigation — thin wrapper that calls SetProcessMitigationPolicy
 * and silently ignores ERROR_NOT_SUPPORTED (policy unknown to this OS
 * version) while propagating genuine failures.
 */
static int
apply_mitigation(PROCESS_MITIGATION_POLICY policy, void *buf, size_t len)
{
    if (SetProcessMitigationPolicy(policy, buf, (SIZE_T)len))
        return 0;
    /* Older OS versions return ERROR_INVALID_PARAMETER for unknown policies. */
    DWORD err = GetLastError();
    if (err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_PARAMETER)
        return 0;   /* skip gracefully — policy not available on this build */
    return -1;
}

/*
 * op_seccomp_lockdown — comprehensive Win32 process mitigations.
 *
 * Applied policies (each guarded by apply_mitigation so the function
 * succeeds even on older Windows builds that don't know a given policy):
 *
 *   ProcessDEPPolicy (XP SP3+)
 *     DEP permanent, no ATL thunk emulation.  NX enforcement is permanent
 *     and cannot be disabled by the process or its children.
 *
 *   ProcessASLRPolicy (Vista+)
 *     Force-randomise images not compiled with /DYNAMICBASE; high-entropy
 *     bottom-up ASLR for 64-bit; require ASLR on all images.
 *
 *   ProcessDynamicCodePolicy (Win10 1511+)
 *     ProhibitDynamicCode: prevent VirtualAlloc(PAGE_EXECUTE_READWRITE),
 *     VirtualProtect to executable, and CreateFileMapping(SEC_IMAGE).
 *     This is the Windows equivalent of the Linux DENY_IF_PROT_EXEC BPF
 *     filter: no process memory can be made executable at runtime.
 *     AllowThreadOptOut = 0: no thread may opt out.
 *
 *   ProcessStrictHandleCheckPolicy (Vista+)
 *     RaiseExceptionOnInvalidHandleReference: invalid HANDLEs throw a
 *     structured exception rather than silently returning NULL, exposing
 *     use-after-close bugs.
 *
 *   ProcessExtensionPointDisablePolicy (Win8+)
 *     Disable AppInit_DLLs and SetWindowsHookEx injection vectors —
 *     a common DLL injection technique used by rootkits and spyware.
 *
 *   ProcessSignaturePolicy (Win8.1+)
 *     MicrosoftSignedOnly = 1: only Microsoft-signed DLLs may be loaded.
 *     This blocks unsigned third-party DLL injection entirely.
 *     Applied with apply_mitigation so it is skipped on Win8 and earlier.
 *
 *   ProcessImageLoadPolicy (Win10 1607+)
 *     NoRemoteImages: refuse to load images from remote (UNC) paths —
 *     prevents DLL planting attacks from network shares.
 *     PreferSystem32Images: load system DLLs from System32 only.
 *
 *   ProcessSideChannelIsolationPolicy (Win10 1809+)
 *     SmtProhibited: prevent sharing an SMT (hyperthreading) core with
 *     another process — hardens against Spectre/MDS cross-thread attacks.
 *     IsolateSecurityDomain = 1: full side-channel isolation for this
 *     process.  Applied with apply_mitigation on older builds.
 *
 * Returns 0 if all available policies applied successfully.
 */
int
op_seccomp_lockdown(void)
{
    int ok = 1;

    /* DEP: permanent NX, no ATL thunk emulation. */
    PROCESS_MITIGATION_DEP_POLICY dep = {0};
    dep.Enable                  = 1;
    dep.Permanent               = 1;
    dep.DisableAtlThunkEmulation = 1;
    if (apply_mitigation(ProcessDEPPolicy, &dep, sizeof dep) < 0) ok = 0;

    /* ASLR: force-randomise, high-entropy, require ASLR on all images. */
    PROCESS_MITIGATION_ASLR_POLICY aslr = {0};
    aslr.EnableBottomUpRandomization = 1;
    aslr.EnableForceRelocateImages   = 1;
    aslr.EnableHighEntropy           = 1;
    aslr.DisallowStrippedImages      = 1;
    if (apply_mitigation(ProcessASLRPolicy, &aslr, sizeof aslr) < 0) ok = 0;

    /*
     * Dynamic code prohibition — W^X for Windows.
     * Equivalent to the Linux DENY_IF_PROT_EXEC BPF filter: prevents any
     * VirtualAlloc / VirtualProtect call that would create executable pages.
     */
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp = {0};
    dcp.ProhibitDynamicCode = 1;
    dcp.AllowThreadOptOut   = 0;
    if (apply_mitigation(ProcessDynamicCodePolicy, &dcp, sizeof dcp) < 0) ok = 0;

    /* Strict handle checks: use-after-close → exception, not silent NULL. */
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handles = {0};
    handles.RaiseExceptionOnInvalidHandleReference = 1;
    handles.HandleExceptionsPermanentlyEnabled     = 1;
    if (apply_mitigation(ProcessStrictHandleCheckPolicy,
                         &handles, sizeof handles) < 0) ok = 0;

    /* Extension point disable: AppInit_DLLs, SetWindowsHookEx injection. */
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext = {0};
    ext.DisableExtensionPoints = 1;
    if (apply_mitigation(ProcessExtensionPointDisablePolicy,
                         &ext, sizeof ext) < 0) ok = 0;

    /* Signature policy: only load Microsoft-signed DLLs. */
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig = {0};
    sig.MicrosoftSignedOnly = 1;
    apply_mitigation(ProcessSignaturePolicy, &sig, sizeof sig);   /* best-effort */

    /* Image load policy: no remote images, prefer System32. */
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgload = {0};
    imgload.NoRemoteImages      = 1;
    imgload.PreferSystem32Images = 1;
    apply_mitigation(ProcessImageLoadPolicy, &imgload, sizeof imgload);

    /* Side-channel isolation: no SMT sharing, full security domain. */
#ifdef ProcessSideChannelIsolationPolicy
    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sci = {0};
    sci.SmtProhibited          = 1;
    sci.IsolateSecurityDomain  = 1;
    apply_mitigation(ProcessSideChannelIsolationPolicy, &sci, sizeof sci);
#endif

    /* Hardware stack protection (Intel CET / shadow stack) — Win10 2004+,
     * Intel 11th gen processors or later.  Prevents ROP chains by maintaining
     * a kernel-protected shadow copy of the return address stack. */
#ifdef ProcessUserShadowStackPolicy
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY uss = {0};
    uss.EnableUserShadowStack          = 1;
    uss.EnableUserShadowStackStrictMode = 1;
    uss.AuditUserShadowStack           = 0;
    apply_mitigation(ProcessUserShadowStackPolicy, &uss, sizeof uss);
#endif

    return ok ? 0 : -1;
}

/*
 * op_seccomp_lockdown_shim — same as lockdown for Windows.
 *
 * The shim needs CreateProcess (not prohibited by any of the above
 * policies), so the same mitigation set is appropriate.
 */
int op_seccomp_lockdown_shim(void) { return op_seccomp_lockdown(); }

/*
 * op_shim_harden — Windows shim-specific hardening.
 *
 * In addition to op_seccomp_lockdown(), applies:
 *
 *   ProcessChildProcessPolicy (Win10 1511+)
 *     AuditNoChildProcessCreation = 1 (audit mode, not hard-block): the
 *     shim must create child processes for the ircd, so we cannot set
 *     NoChildProcessCreation = 1.  Audit mode logs any unexpected child
 *     creation to the event log for detection.
 *
 * Note: Windows Job Objects provide the closest equivalent to Linux
 * subreaper (PR_SET_CHILD_SUBREAPER) — assigning the shim and all its
 * children to a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE would
 * ensure orphan cleanup.  This requires restructuring the launch path and
 * is left as a future improvement.
 */
int
op_shim_harden(void)
{
    int ok = 1;
    if (op_seccomp_lockdown() < 0) ok = 0;

    /* Audit child process creation — shim still needs CreateProcess. */
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child = {0};
    child.NoChildProcessCreation      = 0;
    child.AuditNoChildProcessCreation = 1;
    apply_mitigation(ProcessChildProcessPolicy, &child, sizeof child);

    return ok ? 0 : -1;
}

/*
 * op_secure_alloc — VirtualAlloc with guard pages and VirtualLock.
 *
 * Allocates [guard_page][data_pages][guard_page] using two VirtualAlloc
 * calls:
 *   1. MEM_RESERVE the full region (guard + data + guard) to claim a
 *      contiguous virtual address range.
 *   2. MEM_COMMIT only the data pages with PAGE_READWRITE.
 *   3. The guard pages are left in MEM_RESERVE state (no physical backing)
 *      so any access to them raises STATUS_ACCESS_VIOLATION.
 *
 * VirtualLock() pins the data pages in RAM to prevent them reaching the
 * page file (analogous to mlock on POSIX).
 *
 * SecureZeroMemory in op_secure_free() is the Windows equivalent of
 * explicit_bzero: it is not eliminated by the compiler.
 */
void *
op_secure_alloc(size_t len)
{
    if (len == 0) return NULL;

    /* Windows allocation granularity is 64 KB but page size is 4 KB. */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t page   = (size_t)si.dwPageSize;
    if (!page) page = 4096;
    if (len > (size_t)-1 - (2 * page)) return NULL;   /* overflow guard */
    size_t len_pg = (len + page - 1) & ~(page - 1);
    size_t total  = page + len_pg + page;

    /*
     * Reserve the full range; commit only the data pages.
     * Guard pages stay reserved-but-not-committed → ACCESS_VIOLATION on touch.
     */
    void *base = VirtualAlloc(NULL, total, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return NULL;

    void *data = (uint8_t *)base + page;
    if (!VirtualAlloc(data, len_pg, MEM_COMMIT, PAGE_READWRITE)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    VirtualLock(data, len_pg);   /* pin in RAM — best-effort */
    return data;
}

void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0) return;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t page   = (size_t)si.dwPageSize;
    size_t len_pg = (len + page - 1) & ~(page - 1);

    SecureZeroMemory(p, len);       /* compiler-safe zero */
    VirtualUnlock(p, len_pg);
    /* MEM_RELEASE must be called on the original base address. */
    VirtualFree((uint8_t *)p - page, 0, MEM_RELEASE);
}

/* ============================================================
 * Unknown / unsupported platform — safe no-ops
 * ============================================================ */
#else

#include <op_seccomp.h>
#include <stddef.h>
#include <sys/mman.h>

int op_seccomp_lockdown(void)      { return 0; }
int op_seccomp_lockdown_shim(void) { return 0; }
int op_shim_harden(void)           { return 0; }

void *
op_secure_alloc(size_t len)
{
    if (len == 0) return NULL;
#if defined(MAP_ANON)
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
#elif defined(MAP_ANONYMOUS)
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#else
    return NULL;
#endif
    return (p == MAP_FAILED) ? NULL : p;
}

void
op_secure_free(void *p, size_t len)
{
    if (!p || len == 0) return;
    volatile unsigned char *v = (volatile unsigned char *)p;
    for (size_t i = 0; i < len; i++) v[i] = 0;
    munmap(p, len);
}

#endif /* platform */
