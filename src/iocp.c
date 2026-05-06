/*
 * Ophion IRC Daemon
 * iocp.c: Windows I/O Completion Ports event backend + system utility shims.
 *
 * Implements the same readiness-notification contract as epoll/kqueue/io_uring
 * using Windows IOCP.  The trick is "zero-byte overlapped" WSARecv/WSASend:
 * posting a zero-byte recv/send arms a readiness notification — the IOCP fires
 * a completion as soon as the socket becomes readable/writable, without
 * actually transferring any data.  The handler then performs the real I/O.
 *
 * This file also provides Windows equivalents of the POSIX process/time/OS
 * utility functions in unix.c (op_getpid, op_gettimeofday, op_spawn_process,
 * etc.) and the Windows implementation of op_send_fd_buf/op_recv_fd_buf using
 * WSADuplicateSocket (WSAPROTOCOL_INFO), which replaces the SCM_RIGHTS path
 * used on POSIX platforms.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>

#ifdef _WIN32

#include <winsock2.h>
#include <mswsock.h>   /* WSARecv, WSASend extended flags */

/* =========================================================================
 * I/O Completion Port backend
 * ========================================================================= */

/* -------------------------------------------------------------------------
 * Pending I/O descriptor
 *
 * OVERLAPPED *must* be the first member so that a pointer received from
 * GetQueuedCompletionStatus can be cast directly to iocp_pending_t *.
 * ---------------------------------------------------------------------- */

typedef enum { IOCP_OP_READ, IOCP_OP_WRITE } iocp_op_t;

typedef struct iocp_pending
{
	OVERLAPPED  ov;   /* MUST be first — cast target from GetQueuedCompletionStatus */
	op_fde_t   *F;
	iocp_op_t   op;
	uint32_t    gen;  /* snapshot of F->uring_gen when armed; detects stale completions */
} iocp_pending_t;

static HANDLE hCP = NULL;   /* the single completion port for all sockets */

/* -------------------------------------------------------------------------
 * init / setup
 * ---------------------------------------------------------------------- */

int
op_init_netio_iocp(void)
{
	/* One completion port, one worker thread (we're single-threaded). */
	hCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	return hCP != NULL ? 0 : -1;
}

/*
 * Associate a newly opened socket with the completion port and perform the
 * standard Windows socket setup.
 *
 * Called by commio.c's op_open() immediately after the fd is registered.
 * A non-zero return tells commio.c that we handled everything (including
 * non-blocking mode), so it must not attempt the POSIX fcntl/ioctl path.
 *
 * Non-socket handles (pipes, etc.) will fail the ioctlsocket() call but
 * succeed CreateIoCompletionPort(), so we still return 1 — the caller
 * must not pass pipes through the socket I/O path anyway.
 */
int
op_setup_fd_iocp(op_fde_t *F)
{
	HANDLE h;

	if (F == NULL)
		return 0;

	/* Prevent the socket from being inherited by child processes. */
	SetHandleInformation((HANDLE)(ULONG_PTR)F->fd, HANDLE_FLAG_INHERIT, 0);

	/* Set non-blocking mode so that commio.c's synchronous recv/send
	 * calls return WSAEWOULDBLOCK instead of blocking the event loop. */
	if (F->type & OP_FD_SOCKET)
	{
		unsigned long nonb = 1;
		if (ioctlsocket((SOCKET)(ULONG_PTR)F->fd, FIONBIO, &nonb) == SOCKET_ERROR)
		{
			op_get_errno();
			return 0;
		}
	}

	/* Bind the socket to the completion port.  ERROR_INVALID_PARAMETER is
	 * returned when the handle is already associated — treat as success. */
	h = CreateIoCompletionPort((HANDLE)(ULONG_PTR)F->fd, hCP,
	                           (ULONG_PTR)(intptr_t)F->fd, 0);
	if (h == NULL && GetLastError() != ERROR_INVALID_PARAMETER)
		return 0;

	/* Return 1 (non-zero) so commio.c skips the POSIX O_NONBLOCK/ioctl path,
	 * which does not exist on Windows. */
	return 1;
}

/* -------------------------------------------------------------------------
 * Zero-byte overlapped arming helpers
 * ---------------------------------------------------------------------- */

/*
 * Post a zero-byte overlapped read or write to arm a readiness notification.
 * The completion fires when the socket becomes readable/writable; no data
 * is transferred.  On error (socket already dead) we silently discard the
 * pending struct — the actual I/O handler will get the error on the next
 * real recv()/send() call.
 */
static void
iocp_post_io(op_fde_t *F, iocp_op_t op)
{
	WSABUF buf = { 0, NULL };   /* zero-byte buffer */
	int    rc;

	iocp_pending_t *pend = op_malloc(sizeof(*pend));
	memset(&pend->ov, 0, sizeof(pend->ov));
	pend->F   = F;
	pend->op  = op;
	pend->gen = ++F->uring_gen;  /* arm with current generation; detect stale completions */

	if (op == IOCP_OP_READ)
	{
		DWORD flags = 0;
		rc = WSARecv((SOCKET)(ULONG_PTR)F->fd, &buf, 1, NULL, &flags,
		             &pend->ov, NULL);
	}
	else
	{
		rc = WSASend((SOCKET)(ULONG_PTR)F->fd, &buf, 1, NULL, 0,
		             &pend->ov, NULL);
	}

	if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
		op_free(pend);
}

/* -------------------------------------------------------------------------
 * Public backend interface
 * ---------------------------------------------------------------------- */

void
op_setselect_iocp(op_fde_t *F, unsigned int type, PF *handler, void *client_data)
{
	slop_assert(IsFDOpen(F));

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
		if (handler)
			iocp_post_io(F, IOCP_OP_READ);
	}
	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
		if (handler)
			iocp_post_io(F, IOCP_OP_WRITE);
	}
}

/*
 * op_select_iocp — drain completions for up to timeout_ms milliseconds.
 *
 * We drain up to IOCP_BATCH_MAX completions per call so that a flood of
 * incoming connections cannot starve write/timer events indefinitely.
 * On the first GetQueuedCompletionStatus call we honour the full timeout;
 * subsequent calls within the same iteration use a zero timeout (poll).
 */
#define IOCP_BATCH_MAX 64

int
op_select_iocp(long timeout_ms)
{
	int i;
	DWORD wait;

	wait = (timeout_ms < 0) ? INFINITE : (DWORD)timeout_ms;

	for (i = 0; i < IOCP_BATCH_MAX; i++)
	{
		DWORD      bytes = 0;
		ULONG_PTR  key   = 0;
		OVERLAPPED *ov   = NULL;
		BOOL        ok;
		iocp_pending_t *pend;
		op_fde_t   *F;
		iocp_op_t   op;
		uint32_t    gen;

		ok = GetQueuedCompletionStatus(hCP, &bytes, &key, &ov, wait);
		wait = 0;   /* remaining iterations poll */

		if (!ok && ov == NULL)
			break;  /* timeout (or port closed) */

		if (ov == NULL)
			continue;

		pend = (iocp_pending_t *)ov;  /* OVERLAPPED is first member */
		F    = pend->F;
		op   = pend->op;
		gen  = pend->gen;  /* snapshot before free to avoid use-after-free */
		op_free(pend);

		if (F == NULL || !IsFDOpen(F) || gen != F->uring_gen)
			continue;

		if (op == IOCP_OP_READ)
		{
			PF *hdl = F->read_handler;
			F->read_handler = NULL;
			if (hdl)
				hdl(F, F->read_data);
		}
		else /* IOCP_OP_WRITE */
		{
			PF *hdl = F->write_handler;
			F->write_handler = NULL;
			if (hdl)
				hdl(F, F->write_data);
		}
	}

	op_set_time();
	return 0;
}

/* =========================================================================
 * Windows fd-passing via WSADuplicateSocket
 *
 * Packet format (matches the POSIX SCM_RIGHTS wrapper in commio.c):
 *   uint32_t             magic
 *   uint8_t              count    (number of sockets)
 *   WSAPROTOCOL_INFO[n]  protocol info structs
 *   size_t               datasize
 *   uint8_t[datasize]    payload
 * ========================================================================= */

#define MAGIC_CONTROL  0xFF0ACAFE
#define FD_PASS_MAX    4          /* max sockets per message */

/* Static buffer: largest message = magic(4) + count(1) + 4*WSAPROTOCOL_INFO
 * + size(8) + payload.  In practice payload is tiny; 16 KiB is generous. */
static uint8_t fd_buf[16384];

static int
make_wsaprotocol_info(pid_t process, op_fde_t *F, WSAPROTOCOL_INFO *out)
{
	return WSADuplicateSocket((SOCKET)(ULONG_PTR)op_get_fd(F),
	                          (DWORD)process, out) == 0;
}

static op_fde_t *
make_fde_from_wsaprotocol_info(WSAPROTOCOL_INFO *info)
{
	SOCKET t = WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
	                     FROM_PROTOCOL_INFO, info, 0, 0);
	if (t == INVALID_SOCKET)
	{
		op_get_errno();
		return NULL;
	}
	op_fde_t *F = op_open((op_platform_fd_t)(ULONG_PTR)t,
	                       OP_FD_SOCKET, "remote_socket");
	if (F != NULL)
		op_set_nb(F);
	return F;
}

int
op_send_fd_buf(op_fde_t *xF, op_fde_t **F, int count,
               void *data, size_t datasize, pid_t pid)
{
	size_t bufsize = sizeof(uint32_t) + sizeof(uint8_t)
	               + (sizeof(WSAPROTOCOL_INFO) * (size_t)count)
	               + sizeof(size_t) + datasize;

	if (count < 0 || count > FD_PASS_MAX || bufsize > sizeof(fd_buf))
	{
		errno = EINVAL;
		return -1;
	}

	uint8_t *ptr = fd_buf;
	uint32_t magic = MAGIC_CONTROL;
	memset(fd_buf, 0, bufsize);

	memcpy(ptr, &magic, sizeof(magic));     ptr += sizeof(magic);
	*ptr = (uint8_t)count;                  ptr += sizeof(uint8_t);

	for (int i = 0; i < count; i++)
	{
		make_wsaprotocol_info((pid_t)pid, F[i], (WSAPROTOCOL_INFO *)ptr);
		ptr += sizeof(WSAPROTOCOL_INFO);
	}

	memcpy(ptr, &datasize, sizeof(size_t)); ptr += sizeof(size_t);
	if (datasize > 0)
		memcpy(ptr, data, datasize);

	return op_write(xF, fd_buf, bufsize);
}

int
op_recv_fd_buf(op_fde_t *F, void *data, size_t datasize,
               op_fde_t **xF, int nfds)
{
	size_t minsize = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(size_t);
	uint32_t magic;
	uint8_t  count;
	size_t   datalen;
	ssize_t  ret;

	memset(fd_buf, 0, sizeof(fd_buf));
	ret = op_read(F, fd_buf, sizeof(fd_buf));
	if (ret <= 0)
		return (int)ret;
	if ((size_t)ret < minsize)
	{
		errno = EINVAL;
		return -1;
	}

	uint8_t *ptr = fd_buf;
	memcpy(&magic, ptr, sizeof(magic));   ptr += sizeof(magic);
	if (magic != MAGIC_CONTROL)
	{
		errno = EAGAIN;
		return -1;
	}
	count = *ptr;                         ptr += sizeof(uint8_t);

	for (unsigned int i = 0; i < count && i < (unsigned int)nfds; i++)
	{
		op_fde_t *tF = make_fde_from_wsaprotocol_info((WSAPROTOCOL_INFO *)ptr);
		if (tF == NULL)
			return -1;
		xF[i] = tF;
		ptr += sizeof(WSAPROTOCOL_INFO);
	}

	memcpy(&datalen, ptr, sizeof(size_t)); ptr += sizeof(size_t);
	size_t take = datalen < datasize ? datalen : datasize;
	if (take > 0)
		memcpy(data, ptr, take);
	return (int)take;
}

/* =========================================================================
 * Windows system utility shims (POSIX equivalents live in unix.c)
 * ========================================================================= */

pid_t
op_getpid(void)
{
	return (pid_t)GetCurrentProcessId();
}

/*
 * op_gettimeofday — microsecond-resolution wall clock via GetSystemTimeAsFileTime.
 *
 * Windows FILETIME counts 100-nanosecond intervals since 1601-01-01; we
 * subtract the offset to the Unix epoch (1970-01-01) then convert units.
 */
typedef union { unsigned __int64 ft_i64; FILETIME ft_val; } FT_t;

#ifdef __GNUC__
# define EPOCH_CONST64(x)  (x##ULL)
#else
# define EPOCH_CONST64(x)  (x##ui64)
#endif
/* 100-nanosecond intervals from 1601-01-01 to 1970-01-01 */
#define EPOCH_BIAS  EPOCH_CONST64(116444736000000000)

int
op_gettimeofday(struct timeval *tp, void *not_used)
{
	(void)not_used;
	FT_t ft;
	GetSystemTimeAsFileTime(&ft.ft_val);
	tp->tv_sec  = (long)((ft.ft_i64 - EPOCH_BIAS) / EPOCH_CONST64(10000000));
	tp->tv_usec = (long)((ft.ft_i64 % EPOCH_CONST64(10000000)) / EPOCH_CONST64(10));
	return 0;
}

pid_t
op_spawn_process(const char *path, const char **argv)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	char cmdline[32768];
	size_t pos = 0;

	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	/* Quoted application path */
	if (pos < sizeof(cmdline) - 1) cmdline[pos++] = '"';
	for (const char *p = path; *p && pos < sizeof(cmdline) - 2; p++)
		cmdline[pos++] = *p;
	if (pos < sizeof(cmdline) - 1) cmdline[pos++] = '"';

	if (argv != NULL)
	{
		for (int i = 1; argv[i] != NULL && pos < sizeof(cmdline) - 2; i++)
		{
			if (pos < sizeof(cmdline) - 1) cmdline[pos++] = ' ';
			for (const char *p = argv[i]; *p && pos < sizeof(cmdline) - 2; p++)
				cmdline[pos++] = *p;
		}
	}
	cmdline[pos] = '\0';

	if (!CreateProcessA(path, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
		return -1;

	DWORD pid = pi.dwProcessId;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return (pid_t)pid;
}

pid_t
op_waitpid(pid_t pid, int *status, int flags)
{
	DWORD timeout = (flags & WNOHANG) ? 0 : INFINITE;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
	                              TRUE, (DWORD)pid);
	if (!hProcess)
	{
		errno = ECHILD;
		return -1;
	}

	DWORD waitcode = WaitForSingleObject(hProcess, timeout);
	if (waitcode == WAIT_TIMEOUT)
	{
		CloseHandle(hProcess);
		return 0;
	}
	if (waitcode == WAIT_OBJECT_0 && GetExitCodeProcess(hProcess, &waitcode))
	{
		*status = (int)((waitcode & 0xff) << 8);
		CloseHandle(hProcess);
		return pid;
	}
	CloseHandle(hProcess);
	return -1;
}

int
op_setenv(const char *name, const char *value, int overwrite)
{
	if (name == NULL || value == NULL)
		return -1;
	if (!overwrite)
	{
		char *existing = getenv(name);
		if (existing != NULL && existing[0] != '\0')
			return 0;
	}
	int len = (int)(strlen(name) + strlen(value) + 2);
	char *buf = op_malloc((size_t)len);
	snprintf(buf, (size_t)len, "%s=%s", name, value);
	/* Windows CRT putenv() copies the string — freeing buf afterwards is safe. */
	int r = putenv(buf);
	op_free(buf);
	return r;
}

int
op_kill(pid_t pid, int sig)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, TRUE, (DWORD)pid);
	if (!hProcess)
	{
		errno = EINVAL;
		return -1;
	}

	int ret = -1;
	switch (sig)
	{
	case 0:
		/* Existence check — no signal sent. */
		ret = 0;
		break;
#ifdef SIGHUP
	case SIGHUP:
		/* No SIGHUP semantics on Windows; treat as no-op. */
		ret = 0;
		break;
#endif
	default:
		if (TerminateProcess(hProcess, (UINT)sig))
			ret = 0;
		break;
	}
	CloseHandle(hProcess);
	return ret;
}

void
op_sleep(unsigned int seconds, unsigned int useconds)
{
	(void)useconds;
	Sleep(seconds * 1000u);
}

static const char *
wsa_strerror(int error)
{
	switch (error)
	{
	case 0:                   return "Success";
	case WSAEINTR:            return "Interrupted system call";
	case WSAEBADF:            return "Bad file number";
	case WSAEACCES:           return "Permission denied";
	case WSAEFAULT:           return "Bad address";
	case WSAEINVAL:           return "Invalid argument";
	case WSAEMFILE:           return "Too many open sockets";
	case WSAEWOULDBLOCK:      return "Operation would block";
	case WSAEINPROGRESS:      return "Operation now in progress";
	case WSAEALREADY:         return "Operation already in progress";
	case WSAENOTSOCK:         return "Socket operation on non-socket";
	case WSAEDESTADDRREQ:     return "Destination address required";
	case WSAEMSGSIZE:         return "Message too long";
	case WSAEPROTOTYPE:       return "Protocol wrong type for socket";
	case WSAENOPROTOOPT:      return "Bad protocol option";
	case WSAEPROTONOSUPPORT:  return "Protocol not supported";
	case WSAESOCKTNOSUPPORT:  return "Socket type not supported";
	case WSAEOPNOTSUPP:       return "Operation not supported on socket";
	case WSAEPFNOSUPPORT:     return "Protocol family not supported";
	case WSAEAFNOSUPPORT:     return "Address family not supported";
	case WSAEADDRINUSE:       return "Address already in use";
	case WSAEADDRNOTAVAIL:    return "Can't assign requested address";
	case WSAENETDOWN:         return "Network is down";
	case WSAENETUNREACH:      return "Network is unreachable";
	case WSAENETRESET:        return "Net connection reset";
	case WSAECONNABORTED:     return "Software caused connection abort";
	case WSAECONNRESET:       return "Connection reset by peer";
	case WSAENOBUFS:          return "No buffer space available";
	case WSAEISCONN:          return "Socket is already connected";
	case WSAENOTCONN:         return "Socket is not connected";
	case WSAESHUTDOWN:        return "Can't send after socket shutdown";
	case WSAETOOMANYREFS:     return "Too many references, can't splice";
	case WSAETIMEDOUT:        return "Connection timed out";
	case WSAECONNREFUSED:     return "Connection refused";
	case WSAELOOP:            return "Too many levels of symbolic links";
	case WSAENAMETOOLONG:     return "File name too long";
	case WSAEHOSTDOWN:        return "Host is down";
	case WSAEHOSTUNREACH:     return "No route to host";
	case WSAENOTEMPTY:        return "Directory not empty";
	case WSAEPROCLIM:         return "Too many processes";
	case WSAEUSERS:           return "Too many users";
	case WSAEDQUOT:           return "Disc quota exceeded";
	case WSAESTALE:           return "Stale NFS file handle";
	case WSAEREMOTE:          return "Too many levels of remote in path";
	case WSASYSNOTREADY:      return "Network system is unavailable";
	case WSAVERNOTSUPPORTED:  return "Winsock version out of range";
	case WSANOTINITIALISED:   return "WSAStartup not yet called";
	case WSAEDISCON:          return "Graceful shutdown in progress";
	case WSAHOST_NOT_FOUND:   return "Host not found";
	case WSANO_DATA:          return "No host data of that type was found";
	default:                  return strerror(error);
	}
}

char *
op_strerror(int error)
{
	static char buf[128];
	op_strlcpy(buf, wsa_strerror(error), sizeof(buf));
	return buf;
}

const char *
op_path_to_self(void)
{
	static char path_buf[MAX_PATH];
	GetModuleFileNameA(NULL, path_buf, MAX_PATH);
	return path_buf;
}

#else /* !_WIN32 */

/* Stub implementations for non-Windows builds so the linker is happy. */
int  op_init_netio_iocp(void)   { return -1; }
int  op_setup_fd_iocp(op_fde_t *F) { (void)F; return -1; }
void op_setselect_iocp(op_fde_t *F, unsigned int type, PF *handler, void *client_data)
{
	(void)F; (void)type; (void)handler; (void)client_data;
}
int  op_select_iocp(long timeout_ms) { (void)timeout_ms; return -1; }

#endif /* _WIN32 */
