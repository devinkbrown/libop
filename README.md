# libop

libop is the runtime support library for the Ophion IRC server.  It
provides portable I/O multiplexing, TLS, memory management, data
structures, and network utilities used throughout the server.

libop originated as a fork of libratbox (the support library in
ircd-ratbox/charybdis), but has since diverged so significantly that it
is no longer compatible with or a drop-in replacement for libratbox.

## Notable changes from libratbox

- **I/O backends** — epoll, kqueue, /dev/poll, SIGIO, select, poll, and
  io\_uring (Linux 5.1+) backends; the active backend is selected at
  startup and can be forced via `LIBOP_USE_IOTYPE`.
- **io\_uring kTLS peek-recv** — on kernels where `POLL_ADD` silently
  stalls for kTLS sockets (kernel 6.x), the uring backend transparently
  uses `io_uring_prep_recv(MSG_PEEK)` as the data-availability
  notification mechanism.  The kernel holds the recv SQE async until
  data arrives, bypassing the broken poll wakeup.  On kernel 7.0+ with
  working multishot poll, the standard poll path is used instead.
- **sendbuf** — a dedicated send-buffer layer (`op_sendbuf_*`) separate
  from the receive linebuf, allowing vectored writes and zero-copy paths.
- **linebuf** — the `op_linebuf_*` API handles arbitrary-length IRC lines;
  the old 512-byte hard limit is no longer enforced at this layer.
- **op\_htab** — Robin Hood open-addressing hash table (`op_htab_*`) used
  for all string-keyed lookups throughout the server: nick/channel tables,
  account and service dictionaries, configuration lookups, target-change
  tracking, and more.  Provides O(1) amortised insert, lookup, and delete
  with better cache locality than tree-based structures.  Key API:
  `op_htab_get_or_set` (single-probe get-or-insert), `op_htab_iter_del`
  (safe delete-during-iteration with iterator rewind), `op_htab_compact`
  (manual shrink after bulk deletes).
- **op\_dictionary / op\_radixtree removed** — both the AVL-tree ordered
  dictionary and the Patricia-trie dictionary have been removed from libop.
  All tables have been migrated to `op_htab`.
- **Block allocator** — `op_bh_*` slab/block-heap allocator for
  high-churn objects (clients, channels, ban entries).
- **arc4random** — cryptographically-strong PRNG using ChaCha20 with automatic
  reseeding from the OS entropy source; thread-safe with per-thread state.
- **op\_utf8** — UTF-8 validation, safe truncation without splitting multi-byte
  sequences, U+FFFD sanitisation, and code-point iteration.  Used by the
  `utf8-only` IRCv3 CAP and topic/message length enforcement.
- **op\_ratelimit** — header-only token-bucket rate limiter.  Zero overhead (all
  static inline), no allocation.  Used for per-client flood control, channel flood
  gates, and PRIVMSG/NOTICE burst limiting.
- **op\_lru** — fixed-capacity LRU cache backed by `op_htab` (O(1) get/set/evict).
  Optional `evict_cb` for resource cleanup.  Used for DNS TTL caching and session
  caches.  Both case-sensitive and IRC case-insensitive key variants available.
- **op\_htab\_merge** — merge one hash table into another with a caller-supplied
  conflict handler for key collisions.
- **op\_strbuf\_join / op\_strbuf\_repeat** — join a string array with a separator,
  and repeat a string N times; convenience additions to the strbuf builder.
- **op\_base64url** — RFC 4648 §5 base64url encode/decode (`-_` instead of `+/`,
  no padding); used by WebSocket and modern token protocols.
- **Removed: patricia trie (ip_patricia)** — `op_patricia` has been
  removed.  IP-address lookups that formerly used the patricia trie now
  use open-addressing hash tables embedded in the ircd (see
  `ircd/reject.c` and `ircd/s_conf.c`).

## Memory allocation wrappers

`op_memory.h` (included via `op_lib.h`) provides thin wrappers around the
standard C allocators that **abort via `op_outofmemory()` instead of
returning NULL** — eliminating the need for call-site NULL checks:

| Function | Equivalent to |
|----------|---------------|
| `op_malloc(size)` | `calloc(1, size)` — zero-initialised |
| `op_calloc(nmemb, size)` | `calloc(nmemb, size)` — zero-initialised |
| `op_realloc(ptr, size)` | `realloc(ptr, size)` |
| `op_free(ptr)` | `free(ptr)` — no-op on NULL |
| `op_strdup(s)` | `strdup(s)` |
| `op_strndup(s, n)` | bounded copy into a fresh `malloc(n)` buffer |

Use `op_calloc` when allocating arrays or when the nmemb/size split matters
for overflow-safe size arithmetic.  Use `op_malloc` for single-object
allocations where you just want a zeroed block.

For high-churn objects (clients, channels, ban entries) prefer the block
heap allocator (`op_bh_*`) described below.

## Type conventions

libop uses the following type conventions throughout its public API:

- **Buffer sizes and byte counts** — `size_t`.  All length parameters on
  `op_rawbuf_append`, `op_rawbuf_get`, `op_base64_encode/decode`,
  `op_inet_ntop`, and similar functions accept `size_t` rather than `int`.
  `op_rawbuf_length` returns `size_t`.

- **Collection sizes** — `size_t`.  `op_htab_size` returns `size_t`.

- **Struct fields that represent counts or offsets** — `size_t` or
  `unsigned int`, never signed `int`.  This applies to
  `_rawbuf_head::{len,written}`, `_rawbuf::len`, `buf_head_t::alloclen`,
  `buf_head_t::writeofs`, `buf_head_t::numlines`, and `buf_line_t::refcount`.

- **Functions that flush I/O** — still return `int` (negative on error,
  positive bytes written) to interoperate with the POSIX `write`/`writev`
  convention and the rest of the fd layer.

- **Assertions** — always use `lop_assert()`, not the bare POSIX `assert()`.
  `lop_assert` is wired to libop's logging and restart hooks; bare `assert`
  is not.

## Thread safety

Most of this library is **not thread-safe**.  Do not use it from multiple
threads without external locking.

## Linebuf notes

The linebuf layer buffers incoming and outgoing data in line-granular
chunks to simplify IRC protocol handling.  A terminated linebuf always
ends with CR/LF (and a NUL when read back via `op_linebuf_get`).
`linebuf->overflow` is set if incoming data exceeds the configured
per-line limit and the excess was discarded.

## Sandbox and Secure Memory (`op_seccomp.h`)

Privilege reduction and secure memory for daemon processes.  Full API in
`libop/include/op_seccomp.h`.

### Syscall filters

```c
int op_seccomp_lockdown(void);
```

Installs a BPF deny-list filter for helper daemons (ssld, wsockd, discordd,
authproc) that never spawn children.  Denies exec/fork/ptrace, eBPF, kexec,
keyring, namespaces, perf_event_open, io_uring, SysV shm, module loading,
chroot, I/O ports, personality (ASLR disable), vmsplice/splice/tee, mount,
memfd_create, file-handle-based open, Landlock, membarrier, the seccomp
syscall itself, pidfd FD-theft primitives (pidfd_getfd, pidfd_send_signal),
process_madvise, kcmp, real-time scheduling, and W^X (`mmap`/`mprotect`/
`pkey_mprotect` with `PROT_EXEC`).  All other syscalls are allowed.

```c
int op_seccomp_lockdown_shim(void);
```

Shim-appropriate filter.  Fork/exec/clone are **allowed** (shim must restart
the ircd).  Additional restrictions:
- `socket(domain)` — only `AF_UNIX` (1) allowed; any other domain kills
- `connect(2)` — always killed
- `clone(2)` — killed if any `CLONE_NEW*` namespace flag is set
- Same deny-list as `op_seccomp_lockdown()` except: `seccomp` itself and
  `pidfd_open` are not denied (ircd needs seccomp; shim uses pidfd_open)

On Linux: seccomp BPF with `SECCOMP_FILTER_FLAG_TSYNC` (all threads
atomically) falling back to `prctl(PR_SET_SECCOMP)`.  On OpenBSD: `pledge`.
On FreeBSD: `cap_enter` for helpers; no-op for shim.

### Process hardening

```c
int op_shim_harden(void);
```

Call at the very start of `ophion-shim` main(), before any listener sockets
or child processes.  Applies:
- `PR_SET_DUMPABLE 0` — no core dumps; prevents `/proc/PID/mem` writes
- `RLIMIT_CORE = 0` — belt-and-suspenders
- `PR_SET_CHILD_SUBREAPER 1` — orphaned grandchildren reparent to the shim
- `PR_SET_NO_NEW_PRIVS 1` — blocks setuid/setgid escalation permanently

### Secure memory

```c
void *op_secure_alloc(size_t len);
void  op_secure_free(void *p, size_t len);
```

`op_secure_alloc` allocates zeroed memory with layered protection:
1. `memfd_secret(2)` (Linux ≥ 5.14) — kernel-isolated; invisible to
   `/proc/PID/mem` and ptrace even as root
2. `MAP_ANONYMOUS` + `MADV_WIPEONFORK` fallback — any fork sees zeroed pages
3. Guard pages — one `PROT_NONE` page before and after the usable region;
   overflow/underflow causes immediate SIGSEGV instead of silent corruption
4. `MADV_DONTDUMP` — excluded from core dumps
5. `mlock()` — pinned in RAM; key material never reaches swap
6. `PR_SET_VMA_ANON_NAME "ophion-secure"` (Linux ≥ 5.17) — labels the region
   in `/proc/PID/maps` for security auditing tools

`op_secure_free` calls `explicit_bzero(p, len)` before `munmap()`.

`len` must equal the value originally passed to `op_secure_alloc()`.
Safe to call with `p == NULL`.

## Helper processes

The helper API (`op_helper_*`) spawns and manages child processes that
communicate with the parent over a socket pair.  Used by the authentication
daemon (`authd`) and the ban-check daemon (`bandb`).

TLS and WebSocket handling are **not** helper processes — both run in-process
via `libop/opssl_backend.c` and `libop/websocket.c` respectively.  The former
external `ssld` and `wsockd` subprocesses were retired.

The DNS resolver is **not** a helper process — it runs entirely in-process
inside the ircd (`ircd/res.c`) using a single UDP socket registered with the
libop event loop via `op_socket` / `op_setselect` / `op_event_add`.

## TLS (opssl backend)

TLS is provided by opssl — ophion's own TLS library — via
`libop/src/opssl_backend.c`.  opssl has no external dependencies and is always
compiled in; there is no no-SSL build path.

### Key public API (`commio-ssl.h`)

| Function | Description |
|----------|-------------|
| `op_init_ssl()` | Initialise the opssl library.  Must be called once at startup. |
| `op_setup_ssl_server(cert, key, dh, ciphers, verify)` | Load server certificate, private key, DH parameters, and cipher list into the global TLS context.  Safe to call again on `REHASH`. |
| `op_setup_ssl_server_sni(hostname, cert, key, dh, ciphers, verify)` | Register a per-hostname TLS context for SNI-based certificate selection.  Up to 64 entries. |
| `op_ssl_listen(F, backlog, defer_accept)` | Mark a socket as a TLS listen socket and call `op_listen`. |
| `op_ssl_accept_setup(srv_F, cli_F, st, addrlen)` | Begin a TLS server handshake on a newly accepted client FD. |
| `op_ssl_start_accepted(F, cb, data, timeout)` | Begin a TLS server handshake on a socket whose TCP accept was handled externally. |
| `op_ssl_start_connected(F, cb, data, timeout)` | Begin a TLS client handshake on an already-connected socket (S2S). |
| `op_connect_tcp_ssl(F, dest, local, cb, data, timeout, sni)` | Connect and perform a TLS client handshake in one call (DoT, S2S). |
| `op_ssl_read(F, buf, count)` | Read plaintext from a TLS session. |
| `op_ssl_write(F, buf, count)` | Write plaintext to a TLS session. |
| `op_ssl_shutdown(F)` | Send `close_notify` and free the TLS session. |
| `op_ssl_is_ktls(F)` | Returns `true` if the connection has been offloaded to Linux kernel TLS (kTLS). |
| `op_ssl_export(F, buf, buflen)` | Export the TLS session state into `buf`.  Returns bytes written, or -1 on error. |
| `op_ssl_adopt_exported(F, buf, len)` | Reconstruct a TLS session on `F` from a blob produced by `op_ssl_export`.  Returns 0 on success, -1 on error. |
| `op_get_ssl_certfp(F, buf, method)` | Compute a TLS client certificate fingerprint (SHA-1/256/512, SHA-3, SPKI variants). |

### SNI (Server Name Indication)

`op_setup_ssl_server_sni()` adds entries to a fixed table (`SNI_CTX_MAX = 64`).
During each TLS handshake the SNI callback looks up the client's requested
hostname and switches the session to the matching per-hostname context before
the handshake completes.

### TLS Live Migration (/UPGRADE)

Ophion supports transferring established TLS client connections across a binary
`/UPGRADE` without disconnecting the client.  Two paths are tried in order of
preference:

#### 1. Kernel TLS (kTLS) — `HAVE_KERNEL_TLS`

After a successful TLS handshake using an AEAD cipher (AES-128-GCM,
AES-256-GCM, or ChaCha20-Poly1305), ophion can promote the connection to Linux
kernel TLS.  The backend extracts keys via `opssl_conn_get_write_key()` /
`opssl_conn_get_read_key()` / `opssl_conn_get_write_iv()` /
`opssl_conn_get_read_iv()`, calls `setsockopt(SOL_TCP, TCP_ULP, "tls")` and
then `setsockopt(SOL_TLS, TLS_TX/RX)`.  `op_ssl_read`/`op_ssl_write` then
bypass opssl and call `recvmsg`/`send` directly.

When kTLS is active, `op_ssl_is_ktls(F)` returns `true` and the socket FD is
transferred via `SCM_RIGHTS`; the kernel continues handling all crypto in the
new process without any re-handshake.

`op_ssl_read` with kTLS uses `recvmsg` with a `cmsg` buffer to detect
non-application-data TLS records (alerts, TLS 1.3 handshake messages) delivered
by the kernel — both via `EBADMSG` (device kTLS / kernel < 4.17) and via
`TLS_GET_RECORD_TYPE` cmsg (software kTLS / kernel ≥ 4.17).

Prerequisite: `sudo modprobe tls` (or `CONFIG_TLS=y` in the kernel build).

Log tag after each handshake: `[kTLS]`.

#### 2. Graceful reconnect (fallback)

When kTLS is unavailable, TLS clients receive a `close_notify` and must
reconnect within `MIGRATE_PENDING_TTL` seconds (default 30 s) to restore
channels, account, and modes silently.

### DNS-over-TLS (DoT)

Outgoing DNS queries use a dedicated client TLS context (`ssl_client_ctx`)
with TLS 1.3 preferred.  Per-session ALPN `"dot"` (RFC 7858 §3.2) is
advertised — but **only** for connections that supply an SNI hostname (DoT
resolver addresses).  S2S links reuse the same `ssl_client_ctx` without the
ALPN advertisement.

Post-handshake drain: after the TLS handshake succeeds, a loop drains any
buffered TLS records (NewSessionTicket, etc.) before the first DNS query is
sent.  The loop peeks the socket after each `NEED_READ` to determine whether
more data is buffered, capping at 32 iterations.

### opssl crypto primitives

opssl provides all cryptographic primitives needed by ophion:

- **Hash**: SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- **MAC**: HMAC-SHA-256/384/512
- **KDF**: HKDF, PBKDF2
- **AEAD**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Key exchange**: X25519, P-256, P-384
- **Signatures**: Ed25519, ECDSA (P-256/P-384), RSA (PKCS#1 v1.5, PSS)
- **Post-quantum**: ML-KEM-768, ML-KEM-1024
- **X.509**: DER parsing, certificate chain verification, fingerprinting
- **Base64**: standard and URL-safe encode/decode
