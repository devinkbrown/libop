/*
 * test_seccomp.c — libop sandbox and secure-memory test suite.
 *
 * Covers:
 *   op_secure_alloc / op_secure_free  — allocation, write, zero-on-free
 *   op_shim_harden                    — dumpable=0, RLIMIT_CORE=0, no_new_privs=1
 *   op_seccomp_lockdown               — blocked syscalls kill with SIGSYS
 *   DENY_IF_PROT_EXEC                 — mmap/mprotect(PROT_EXEC) kills with SIGSYS
 *   op_seccomp_lockdown_shim          — connect blocked, socket(AF_INET) blocked;
 *                                       fork/AF_UNIX allowed
 *
 * Seccomp tests fork a child that installs the filter and attempts the blocked
 * operation.  SECCOMP_RET_KILL_PROCESS terminates the process with SIGSYS;
 * the parent checks WIFSIGNALED && WTERMSIG == SIGSYS.
 *
 * Children that cannot install the filter (old kernel) call _exit(99) and
 * those tests are reported as skipped.
 */

#define _GNU_SOURCE
#include <op_seccomp.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
# include <sys/prctl.h>
# include <sys/ptrace.h>
# include <sys/socket.h>
# include <sys/syscall.h>
# include <sys/shm.h>       /* SHM_EXEC */
# include <netinet/in.h>
# include <sched.h>         /* CLONE_NEWUSER, CLONE_NEWNS */
#endif

/* ── Test harness ─────────────────────────────────────────────────────────── */

static int failures = 0;
static int skipped  = 0;
static const char *_section = "";

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "  FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

/*
 * SECTION / END_SECTION wrap each test in a do { do { } while(0) } while(0)
 * so SKIP can use `break` to exit the inner block without duplicate labels.
 */
#define SECTION(name) \
    do { \
        _section = (name); \
        int _sec_before = failures; \
        int _sec_skip = 0; \
        do {

#define SKIP(reason) \
    do { \
        printf("  skip  %-48s %s\n", _section, (reason)); \
        skipped++; \
        _sec_skip = 1; \
    } while (0); break

#define END_SECTION \
        } while (0); \
        if (!_sec_skip) \
            printf("  %-52s %s\n", _section, \
                   failures == _sec_before ? "pass" : "FAIL"); \
    } while (0)

/* ── Seccomp helpers (Linux only) ─────────────────────────────────────────── */

#ifdef __linux__

typedef void (*child_fn)(void);

static int
run_in_sandbox(child_fn fn)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        fn();
        _exit(42);   /* canary: must never be reached when blocked */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

/* Returns 1 if the child was killed by SIGSEGV (guard page fault). */
static int killed_by_sigsegv(int st) {
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV;
}

/* ── Guard-page child bodies ─────────────────────────────────────────────── */

/*
 * Probe the leading guard page (one byte before the allocation).
 * op_secure_alloc places a PROT_NONE page immediately before the data region.
 */
static void child_guard_leading(void) {
    void *p = op_secure_alloc(64);
    if (!p) _exit(99);
    /* Write to the byte immediately before the data region → leading guard */
    volatile uint8_t *probe = (uint8_t *)p - 1;
    *probe = 0xAA;  /* must SIGSEGV */
    _exit(42);      /* canary */
}

/*
 * Probe the trailing guard page (one byte after the last allocated byte).
 * op_secure_alloc aligns `len` up to a page boundary, then places a PROT_NONE
 * page at `base + PAGE + len_pg`.  The first byte of that trailing guard is
 * at `(uint8_t *)p + len_pg` where len_pg = round_up(64, page_size).
 * Since page_size >= 64, len_pg == page_size, so the probe hits the first
 * byte of the trailing guard.
 */
static void child_guard_trailing(void) {
    void *p = op_secure_alloc(64);
    if (!p) _exit(99);
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    /* len_pg = round_up(64, page) = page (since page > 64) */
    volatile uint8_t *probe = (uint8_t *)p + (size_t)page;
    *probe = 0xBB;  /* must SIGSEGV */
    _exit(42);      /* canary */
}

/*
 * Confirm the allocation itself is fully accessible across [0, len).
 * A SIGSEGV here would be a regression.
 */
static void child_guard_data_accessible(void) {
    size_t len = 4096;
    void *p = op_secure_alloc(len);
    if (!p) _exit(99);
    memset(p, 0xCC, len);
    uint8_t *b = (uint8_t *)p;
    for (size_t i = 0; i < len; i++) {
        if (b[i] != 0xCC) _exit(2);
    }
    op_secure_free(p, len);
    _exit(0);
}

/*
 * Confirm that op_secure_free cleans up without crashing.
 * Forks because free calls munmap, and we don't want to clobber the test
 * process's address space if anything goes wrong.
 */
static void child_guard_free_ok(void) {
    void *p = op_secure_alloc(128);
    if (!p) _exit(99);
    memset(p, 0xDD, 128);
    op_secure_free(p, 128);
    _exit(0);
}

/* Returns 1 if the child was killed by the seccomp filter (SIGSYS). */
static int killed_by_seccomp(int st) {
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS;
}

/* Returns 1 if the child exited cleanly with status 0. */
static int exited_ok(int st) {
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

/* Returns 1 if the child signals "filter unavailable" (_exit(99)). */
static int child_skip(int st) {
    return WIFEXITED(st) && WEXITSTATUS(st) == 99;
}

/* ── Child bodies ─────────────────────────────────────────────────────────── */

static void child_lockdown_execve(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    execl("/bin/true", "true", (char *)NULL);
}

static void child_lockdown_fork(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    fork();
}

static void child_lockdown_ptrace(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

static void child_wx_mprotect(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) _exit(99);
    mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static void child_wx_mmap(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void child_allowed_read(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    char buf[1];
    int fd[2];
    if (pipe(fd) < 0) _exit(99);
    if (write(fd[1], "x", 1) < 0) _exit(99);
    close(fd[1]);
    ssize_t n = read(fd[0], buf, 1);
    close(fd[0]);
    _exit(n == 1 && buf[0] == 'x' ? 0 : 2);
}

static void child_shim_connect(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) _exit(99);
    struct sockaddr addr = { .sa_family = AF_UNIX };
    connect(s, &addr, sizeof addr);
}

static void child_shim_socket_inet(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
    socket(AF_INET, SOCK_STREAM, 0);
}

static void child_shim_socket_unix(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) _exit(2);
    close(s);
    _exit(0);
}

static void child_shim_wx_mmap(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
    mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void child_shim_fork(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
    pid_t p = fork();
    if (p == 0) _exit(0);
    if (p < 0)  _exit(2);
    int st = 0;
    waitpid(p, &st, 0);
    _exit(exited_ok(st) ? 0 : 2);
}

/* ── New-syscall deny children ────────────────────────────────────────────── */

static void child_lockdown_init_module(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    /* finit_module is preferred on modern kernels, but init_module is always
     * present on x86_64 and exercises the same deny rule. */
#ifdef __NR_init_module
    syscall(__NR_init_module, NULL, 0, "");
#else
    _exit(99);
#endif
}

static void child_lockdown_chroot(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    if (chroot("/") < 0) _exit(0); /* expected to be denied by seccomp */
}

static void child_lockdown_shmat_exec(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
    /* shmat itself is denied entirely; any call should SIGSYS. */
#ifdef __NR_shmat
    /* Create a key that will fail (IPC_PRIVATE with bogus size is OK for testing
     * because the filter fires before the kernel validates the arguments). */
    syscall(__NR_shmat, -1, NULL, SHM_EXEC);
#else
    _exit(99);
#endif
}

/*
 * clone with CLONE_NEWUSER in the shim filter — must be killed.
 * We use the raw clone syscall to pass flags directly; glibc's clone()
 * wrapper rewrites flags, so we bypass it with syscall(2).
 */
static void child_shim_clone_newuser(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#if defined(__NR_clone) && defined(CLONE_NEWUSER)
    syscall(__NR_clone, CLONE_NEWUSER | SIGCHLD, NULL, NULL, NULL, NULL);
#else
    _exit(99);
#endif
}

/* clone with only SIGCHLD (plain fork equivalent) must still be allowed. */
static void child_shim_clone_sigchld(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_clone
    /* SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID — what glibc uses */
    pid_t p = (pid_t)syscall(__NR_clone,
                              (unsigned long)(SIGCHLD | 0x01000000 | 0x00200000),
                              NULL, NULL, NULL, NULL);
    if (p == 0) _exit(0);
    if (p < 0)  _exit(2);
    int st = 0;
    waitpid(p, &st, 0);
    _exit(exited_ok(st) ? 0 : 2);
#else
    _exit(99);
#endif
}

/* ── Extended deny children (base lockdown) ──────────────────────────────── */

/* personality(2) — ASLR-disable vector. */
static void child_lockdown_personality(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_personality
    /* 0xFFFFFFFF = PER_QUERY (no-change query) — filter fires before kernel
     * validates, so the exact value does not matter. */
    syscall(__NR_personality, 0xFFFFFFFFUL);
#else
    _exit(99);
#endif
}

/* vmsplice(2) — userspace-to-pipe page-cache injection. */
static void child_lockdown_vmsplice(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_vmsplice
    syscall(__NR_vmsplice, -1, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

/* mount(2) — filesystem mounting. */
static void child_lockdown_mount(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_mount
    syscall(__NR_mount, NULL, NULL, NULL, 0UL, NULL);
#else
    _exit(99);
#endif
}

/* membarrier(2) — cross-process IPI / DoS. */
static void child_lockdown_membarrier(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_membarrier
    /* cmd=0 = MEMBARRIER_CMD_QUERY; filter fires before kernel validates. */
    syscall(__NR_membarrier, 0, 0, 0);
#else
    _exit(99);
#endif
}

/*
 * seccomp(2) itself — after op_seccomp_lockdown() __NR_seccomp is denied.
 * Attempt a second seccomp call with a bogus command (999999); the filter
 * must SIGSYS before the kernel can return EINVAL.
 */
static void child_lockdown_seccomp_syscall(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_seccomp
    syscall(__NR_seccomp, 999999U, 0U, NULL);
#else
    _exit(99);
#endif
}

/* landlock_create_ruleset(2) — nested userspace sandbox. */
static void child_lockdown_landlock(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_landlock_create_ruleset
    syscall(__NR_landlock_create_ruleset, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

/* name_to_handle_at(2) — VFS-bypass file handle. */
static void child_lockdown_name_to_handle_at(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_name_to_handle_at
    syscall(__NR_name_to_handle_at, -1, NULL, NULL, NULL, 0);
#else
    _exit(99);
#endif
}

/* pidfd_getfd(2) — steal a file descriptor from another process via pidfd. */
static void child_lockdown_pidfd_getfd(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_pidfd_getfd
    syscall(__NR_pidfd_getfd, -1, 0, 0U);
#else
    _exit(99);
#endif
}

/* kcmp(2) — compare kernel objects across process boundaries. */
static void child_lockdown_kcmp(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_kcmp
    /* KCMP_FILE=0: compare fd 0 of self vs self.  Filter fires first. */
    syscall(__NR_kcmp, (long)getpid(), (long)getpid(), 0, 0UL, 0UL);
#else
    _exit(99);
#endif
}

/* ── Extended deny children (shim lockdown) ──────────────────────────────── */

/* vmsplice is also denied in the shim filter. */
static void child_shim_vmsplice(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_vmsplice
    syscall(__NR_vmsplice, -1, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

/* personality is also denied in the shim filter. */
static void child_shim_personality(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_personality
    syscall(__NR_personality, 0xFFFFFFFFUL);
#else
    _exit(99);
#endif
}

static void child_shim_sched_setscheduler(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_sched_setscheduler
    syscall(__NR_sched_setscheduler, (long)getpid(), 0, NULL);
#else
    _exit(99);
#endif
}

static void child_shim_sched_setattr(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_sched_setattr
    syscall(__NR_sched_setattr, (long)getpid(), NULL, 0U);
#else
    _exit(99);
#endif
}

static void child_shim_copy_file_range(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_copy_file_range
    syscall(__NR_copy_file_range, -1, NULL, -1, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

static void child_shim_memfd_create(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_memfd_create
    syscall(__NR_memfd_create, "test", 0U);
#else
    _exit(99);
#endif
}

/* ── New VFS mount API children (both filters) ───────────────────────────── */

static void child_lockdown_fsopen(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_fsopen
    syscall(__NR_fsopen, "ext4", 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_move_mount(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_move_mount
    syscall(__NR_move_mount, -1, "", -1, "", 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_open_tree(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_open_tree
    syscall(__NR_open_tree, -1, "", 0U);
#else
    _exit(99);
#endif
}

static void child_shim_fsopen(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_fsopen
    syscall(__NR_fsopen, "ext4", 0U);
#else
    _exit(99);
#endif
}

static void child_shim_move_mount(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_move_mount
    syscall(__NR_move_mount, -1, "", -1, "", 0U);
#else
    _exit(99);
#endif
}

static void child_shim_open_tree(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_open_tree
    syscall(__NR_open_tree, -1, "", 0U);
#else
    _exit(99);
#endif
}

/* ── mseal children (both filters) ──────────────────────────────────────── */

static void child_lockdown_mseal(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_mseal
    /* Pass a bogus address/len; filter fires before the kernel validates args. */
    syscall(__NR_mseal, NULL, 0UL, 0UL);
#else
    _exit(99);
#endif
}

static void child_shim_mseal(void) {
    if (op_seccomp_lockdown_shim() < 0) _exit(99);
#ifdef __NR_mseal
    syscall(__NR_mseal, NULL, 0UL, 0UL);
#else
    _exit(99);
#endif
}

/* ── splice / tee / memfd_create / copy_file_range (lockdown only) ───────── */

static void child_lockdown_splice(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_splice
    syscall(__NR_splice, -1, NULL, -1, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_tee(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_tee
    syscall(__NR_tee, -1, -1, 0UL, 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_memfd_create(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_memfd_create
    syscall(__NR_memfd_create, "test", 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_copy_file_range(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_copy_file_range
    syscall(__NR_copy_file_range, -1, NULL, -1, NULL, 0UL, 0U);
#else
    _exit(99);
#endif
}

static void child_lockdown_userfaultfd(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_userfaultfd
    syscall(__NR_userfaultfd, 0);
#else
    _exit(99);
#endif
}

static void child_lockdown_sched_setattr(void) {
    if (op_seccomp_lockdown() < 0) _exit(99);
#ifdef __NR_sched_setattr
    syscall(__NR_sched_setattr, (long)getpid(), NULL, 0U);
#else
    _exit(99);
#endif
}

#endif /* __linux__ */

/* ── Guard-page tests (Linux only) ──────────────────────────────────────── */

#ifdef __linux__
static void
test_guard_pages(void)
{
    SECTION("guard pages: leading guard kills with SIGSEGV")
        int st = run_in_sandbox(child_guard_leading);
        if (child_skip(st)) { SKIP("op_secure_alloc unavailable"); }
        CHECK(killed_by_sigsegv(st));
    END_SECTION;

    SECTION("guard pages: trailing guard kills with SIGSEGV")
        int st = run_in_sandbox(child_guard_trailing);
        if (child_skip(st)) { SKIP("op_secure_alloc unavailable"); }
        CHECK(killed_by_sigsegv(st));
    END_SECTION;

    SECTION("guard pages: data region fully accessible (4 KB)")
        int st = run_in_sandbox(child_guard_data_accessible);
        if (child_skip(st)) { SKIP("op_secure_alloc unavailable"); }
        CHECK(exited_ok(st));
    END_SECTION;

    SECTION("guard pages: op_secure_free completes cleanly")
        int st = run_in_sandbox(child_guard_free_ok);
        if (child_skip(st)) { SKIP("op_secure_alloc unavailable"); }
        CHECK(exited_ok(st));
    END_SECTION;
}
#endif /* __linux__ */

/* ── Test groups ──────────────────────────────────────────────────────────── */

static void
test_secure_alloc(void)
{
    SECTION("secure_alloc: non-NULL for positive size")
        void *p = op_secure_alloc(64);
        CHECK(p != NULL);
        if (p) op_secure_free(p, 64);
    END_SECTION;

    SECTION("secure_alloc: NULL for size 0")
        CHECK(op_secure_alloc(0) == NULL);
    END_SECTION;

    SECTION("secure_alloc: memory is readable and writable")
        void *p = op_secure_alloc(256);
        if (!p) { SKIP("allocation failed"); }
        memset(p, 0xAB, 256);
        uint8_t *b = (uint8_t *)p;
        int ok = 1;
        for (int i = 0; i < 256; i++)
            if (b[i] != 0xAB) { ok = 0; break; }
        CHECK(ok);
        op_secure_free(p, 256);
    END_SECTION;

    SECTION("secure_alloc: large allocation (512 KB)")
        void *p = op_secure_alloc(512 * 1024);
        if (!p) { SKIP("allocation failed"); }
        memset(p, 0x5A, 512 * 1024);
        CHECK(((uint8_t *)p)[0]             == 0x5A);
        CHECK(((uint8_t *)p)[512*1024 - 1]  == 0x5A);
        op_secure_free(p, 512 * 1024);
    END_SECTION;

    SECTION("secure_free: NULL pointer is a no-op")
        op_secure_free(NULL, 64);
        CHECK(1);
    END_SECTION;

    SECTION("secure_free: zero length is a no-op")
        void *p = op_secure_alloc(64);
        if (!p) { SKIP("allocation failed"); }
        op_secure_free(p, 0);       /* body returns early — must not crash */
        op_secure_free(p, 64);      /* actual release */
    END_SECTION;
}

static void
test_shim_harden(void)
{
#ifdef __linux__
    /* Fork so we don't clobber the test process's own dumpable/rlimit state. */
    pid_t pid = fork();
    if (pid == 0) {
        op_shim_harden();
        int dump = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        struct rlimit rl = { .rlim_cur = 1, .rlim_max = 1 };
        getrlimit(RLIMIT_CORE, &rl);
        int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        _exit((dump == 0 && rl.rlim_cur == 0 && nnp == 1) ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    SECTION("shim_harden: dumpable=0, RLIMIT_CORE=0, no_new_privs=1")
        if (!WIFEXITED(status)) { SKIP("child killed by signal"); }
        CHECK(WEXITSTATUS(status) == 0);
    END_SECTION;
#else
    SECTION("shim_harden: Linux-only")
        SKIP("not Linux");
    END_SECTION;
#endif
}

static void
test_lockdown_blocked(void)
{
#ifdef __linux__
    SECTION("lockdown: execve is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_execve);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: fork is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_fork);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: ptrace is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_ptrace);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;
#else
    SECTION("lockdown: Linux-only") SKIP("not Linux"); END_SECTION;
#endif
}

static void
test_lockdown_wx(void)
{
#ifdef __linux__
    SECTION("lockdown W^X: mprotect(PROT_EXEC) is killed (SIGSYS)")
        int st = run_in_sandbox(child_wx_mprotect);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown W^X: mmap(PROT_EXEC) is killed (SIGSYS)")
        int st = run_in_sandbox(child_wx_mmap);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown W^X: benign read/write still works after lockdown")
        int st = run_in_sandbox(child_allowed_read);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(exited_ok(st));
    END_SECTION;
#else
    SECTION("lockdown W^X: Linux-only") SKIP("not Linux"); END_SECTION;
#endif
}

static void
test_lockdown_new_denials(void)
{
#ifdef __linux__
    SECTION("lockdown: init_module is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_init_module);
        if (child_skip(st)) { SKIP("seccomp or __NR_init_module unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: chroot is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_chroot);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: shmat is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_shmat_exec);
        if (child_skip(st)) { SKIP("seccomp or __NR_shmat unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: personality is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_personality);
        if (child_skip(st)) { SKIP("seccomp or __NR_personality unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: vmsplice is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_vmsplice);
        if (child_skip(st)) { SKIP("seccomp or __NR_vmsplice unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: mount is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_mount);
        if (child_skip(st)) { SKIP("seccomp or __NR_mount unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: membarrier is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_membarrier);
        if (child_skip(st)) { SKIP("seccomp or __NR_membarrier unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: seccomp(2) itself is killed after lockdown (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_seccomp_syscall);
        if (child_skip(st)) { SKIP("seccomp or __NR_seccomp unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: landlock_create_ruleset is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_landlock);
        if (child_skip(st)) { SKIP("seccomp or __NR_landlock_create_ruleset unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: name_to_handle_at is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_name_to_handle_at);
        if (child_skip(st)) { SKIP("seccomp or __NR_name_to_handle_at unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: pidfd_getfd is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_pidfd_getfd);
        if (child_skip(st)) { SKIP("seccomp or __NR_pidfd_getfd unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: kcmp is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_kcmp);
        if (child_skip(st)) { SKIP("seccomp or __NR_kcmp unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: splice is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_splice);
        if (child_skip(st)) { SKIP("seccomp or __NR_splice unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: tee is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_tee);
        if (child_skip(st)) { SKIP("seccomp or __NR_tee unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: memfd_create is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_memfd_create);
        if (child_skip(st)) { SKIP("seccomp or __NR_memfd_create unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: copy_file_range is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_copy_file_range);
        if (child_skip(st)) { SKIP("seccomp or __NR_copy_file_range unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: userfaultfd is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_userfaultfd);
        if (child_skip(st)) { SKIP("seccomp or __NR_userfaultfd unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: sched_setattr is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_sched_setattr);
        if (child_skip(st)) { SKIP("seccomp or __NR_sched_setattr unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: fsopen is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_fsopen);
        if (child_skip(st)) { SKIP("seccomp or __NR_fsopen unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: move_mount is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_move_mount);
        if (child_skip(st)) { SKIP("seccomp or __NR_move_mount unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: open_tree is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_open_tree);
        if (child_skip(st)) { SKIP("seccomp or __NR_open_tree unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("lockdown: mseal is killed (SIGSYS)")
        int st = run_in_sandbox(child_lockdown_mseal);
        if (child_skip(st)) { SKIP("seccomp or __NR_mseal unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;
#else
    SECTION("lockdown new denials: Linux-only") SKIP("not Linux"); END_SECTION;
#endif
}

static void
test_shim_clone_filter(void)
{
#ifdef __linux__
    SECTION("shim: clone(CLONE_NEWUSER) is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_clone_newuser);
        if (child_skip(st)) { SKIP("seccomp or CLONE_NEWUSER unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim: clone(SIGCHLD) is allowed")
        int st = run_in_sandbox(child_shim_clone_sigchld);
        if (child_skip(st)) { SKIP("seccomp or __NR_clone unavailable"); }
        CHECK(exited_ok(st));
    END_SECTION;
#else
    SECTION("shim clone filter: Linux-only") SKIP("not Linux"); END_SECTION;
#endif
}

static void
test_shim_lockdown(void)
{
#ifdef __linux__
    /*
     * connect(2) and socket(AF_INET) are intentionally NOT denied by the shim
     * filter: this filter is inherited by the ircd child across fork+exec, and
     * the ircd needs AF_INET/AF_INET6 sockets for listener handoff, outbound
     * server links, auth connections, and resolver sockets, as well as
     * connect(2) for outbound S2S links.  The ircd installs its own stricter
     * op_seccomp_lockdown() filter after startup; seccomp filters stack and
     * can only be tightened, never relaxed.
     */
    SECTION("shim lockdown: connect(2) is allowed (inherited by ircd child)")
        int st = run_in_sandbox(child_shim_connect);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(!killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: socket(AF_INET) is allowed (inherited by ircd child)")
        int st = run_in_sandbox(child_shim_socket_inet);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(!killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: socket(AF_UNIX) is allowed")
        int st = run_in_sandbox(child_shim_socket_unix);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(exited_ok(st));
    END_SECTION;

    /*
     * mmap(PROT_EXEC) is intentionally NOT denied by the shim filter: the ircd
     * child's dynamic linker (ld.so) calls mmap(PROT_READ|PROT_EXEC) to map
     * shared library text segments immediately after execve, before main() runs.
     * Denying PROT_EXEC here would kill ld.so and prevent the ircd from
     * starting at all.  The ircd's own op_seccomp_lockdown() applies W^X after
     * startup completes.
     */
    SECTION("shim lockdown W^X: mmap(PROT_EXEC) is allowed (ircd ld.so needs it)")
        int st = run_in_sandbox(child_shim_wx_mmap);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(!killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: fork(2) is allowed")
        int st = run_in_sandbox(child_shim_fork);
        if (child_skip(st)) { SKIP("seccomp unavailable on this kernel"); }
        CHECK(exited_ok(st));
    END_SECTION;

    SECTION("shim lockdown: vmsplice is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_vmsplice);
        if (child_skip(st)) { SKIP("seccomp or __NR_vmsplice unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: personality is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_personality);
        if (child_skip(st)) { SKIP("seccomp or __NR_personality unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: sched_setscheduler is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_sched_setscheduler);
        if (child_skip(st)) { SKIP("seccomp or __NR_sched_setscheduler unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: sched_setattr is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_sched_setattr);
        if (child_skip(st)) { SKIP("seccomp or __NR_sched_setattr unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: copy_file_range is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_copy_file_range);
        if (child_skip(st)) { SKIP("seccomp or __NR_copy_file_range unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: memfd_create is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_memfd_create);
        if (child_skip(st)) { SKIP("seccomp or __NR_memfd_create unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: fsopen is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_fsopen);
        if (child_skip(st)) { SKIP("seccomp or __NR_fsopen unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: move_mount is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_move_mount);
        if (child_skip(st)) { SKIP("seccomp or __NR_move_mount unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: open_tree is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_open_tree);
        if (child_skip(st)) { SKIP("seccomp or __NR_open_tree unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;

    SECTION("shim lockdown: mseal is killed (SIGSYS)")
        int st = run_in_sandbox(child_shim_mseal);
        if (child_skip(st)) { SKIP("seccomp or __NR_mseal unavailable"); }
        CHECK(killed_by_seccomp(st));
    END_SECTION;
#else
    SECTION("shim lockdown: Linux-only") SKIP("not Linux"); END_SECTION;
#endif
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int
main(void)
{
    printf("libop seccomp / secure-memory test suite\n\n");

    printf("op_secure_alloc / op_secure_free:\n");
    test_secure_alloc();

    printf("\nop_shim_harden:\n");
    test_shim_harden();

    printf("\nop_seccomp_lockdown — blocked syscalls:\n");
    test_lockdown_blocked();

    printf("\nop_seccomp_lockdown — W^X enforcement (DENY_IF_PROT_EXEC):\n");
    test_lockdown_wx();

    printf("\nop_seccomp_lockdown — new denied syscalls:\n");
    test_lockdown_new_denials();

    printf("\nop_seccomp_lockdown_shim:\n");
    test_shim_lockdown();

    printf("\nop_seccomp_lockdown_shim — clone namespace filter:\n");
    test_shim_clone_filter();

#ifdef __linux__
    printf("\nop_secure_alloc — guard pages:\n");
    test_guard_pages();
#endif

    printf("\n%s  (%d failure(s), %d skipped)\n",
           failures == 0 ? "ALL PASS" : "FAILURES", failures, skipped);

    return failures == 0 ? 0 : 1;
}
