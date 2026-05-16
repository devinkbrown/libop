/*
 *  Ophion IRC Daemon
 *  libop/src/op_lib.c: Core library initialization, time, formatting, and
 *                      base64 utilities.
 *
 *  Copyright (C) 2005,2006 ircd-ratbox development team
 *  Copyright (C) 2005,2006 Aaron Sethman <androsyn@ratbox.org>
 *  Copyright (C) 2024-2026 Ophion IRC Daemon contributors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_arena.h>
#include <commio-int.h>
#include <commio-ssl.h>
#include <stdatomic.h>

/* -------------------------------------------------------------------------
 * Callbacks — installed once by op_lib_init() before the event loop starts.
 *
 * Stored as _Atomic function pointers so reads from any thread see the
 * initialised value without relying on compiler or CPU ordering guarantees.
 * op_lib_init() stores with memory_order_release; every call site loads with
 * memory_order_acquire, forming a synchronises-with relationship that ensures
 * the pointers are visible to all subsequent callers.
 *
 * These are typed as pointers-to-function-type because C11 _Atomic does not
 * support function types directly, only pointer types.
 * ---------------------------------------------------------------------- */

typedef log_cb     *log_cb_ptr;
typedef restart_cb *restart_cb_ptr;
typedef die_cb     *die_cb_ptr;

static _Atomic log_cb_ptr     op_log     = NULL;
static _Atomic restart_cb_ptr op_restart = NULL;
static _Atomic die_cb_ptr     op_die     = NULL;

/* op_cb_log / op_cb_restart / op_cb_die — inline accessors for the callbacks
 * that issue a single acquire-load so the compiler cannot hoist or sink the
 * read across other operations. */
static inline log_cb *
cb_log(void)
{
	return atomic_load_explicit(&op_log, memory_order_acquire);
}

static inline restart_cb *
cb_restart(void)
{
	return atomic_load_explicit(&op_restart, memory_order_acquire);
}

static inline die_cb *
cb_die(void)
{
	return atomic_load_explicit(&op_die, memory_order_acquire);
}

/* -------------------------------------------------------------------------
 * Wall-clock snapshot.
 *
 * op_time is written exclusively by op_set_time(), which is called from the
 * I/O dispatch thread (the event loop).  op_current_time() and
 * op_current_time_tv() are called from the same thread, so no synchronisation
 * is required for the struct.  op_current_sec is an _Atomic time_t so that
 * other threads (e.g. worker threads checking expiry) can read the coarse
 * current time without a data race.
 * ---------------------------------------------------------------------- */

static struct timeval   op_time;
static _Atomic time_t   op_current_sec = 0;

/* -------------------------------------------------------------------------
 * Date / time name tables — grouped into one struct to keep the data
 * co-located and make the indexing relationship explicit.
 * ---------------------------------------------------------------------- */

static const struct {
	const char *long_wday[7];
	const char *long_mon[12];
	const char *short_wday[7];
	const char *short_mon[12];
} ts_names = {
	.long_wday  = { "Sunday",    "Monday",   "Tuesday", "Wednesday",
	                "Thursday",  "Friday",   "Saturday" },
	.long_mon   = { "January",   "February", "March",   "April",
	                "May",       "June",     "July",    "August",
	                "September", "October",  "November","December" },
	.short_wday = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" },
	.short_mon  = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
	                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" },
};

/* -------------------------------------------------------------------------
 * op_ctime — format a Unix timestamp as "Www Mmm DD HH:MM:SS YYYY" (UTC).
 *
 * If buf is NULL, writes into a per-thread static buffer and returns it.
 * If buf is non-NULL, writes into buf (of size len) and returns buf.
 * Returns an empty string on error (gmtime failure).
 * ---------------------------------------------------------------------- */
char *
op_ctime(time_t t, char *buf, size_t len)
{
	struct tm *tp;
	static _Thread_local char tls_buf[128];
	char *out;
	size_t out_len;

#if defined(HAVE_GMTIME_R)
	struct tm tmr;
	tp = gmtime_r(&t, &tmr);
#else
	tp = gmtime(&t);
#endif

	if (buf == NULL)
	{
		out     = tls_buf;
		out_len = sizeof(tls_buf);
	}
	else
	{
		out     = buf;
		out_len = len;
	}

	if (op_unlikely(tp == NULL))
	{
		op_strlcpy(out, "", out_len);
		return out;
	}

	snprintf(out, out_len, "%s %s %d %02d:%02d:%02d %d",
	         ts_names.short_wday[tp->tm_wday],
	         ts_names.short_mon[tp->tm_mon],
	         tp->tm_mday,
	         tp->tm_hour, tp->tm_min, tp->tm_sec,
	         tp->tm_year + 1900);
	return out;
}

/* -------------------------------------------------------------------------
 * op_date — format a Unix timestamp as the long IRC date string (UTC).
 *
 * Always writes into caller-supplied buf.  Returns buf, or buf containing
 * an empty string on error.
 * ---------------------------------------------------------------------- */
char *
op_date(time_t t, char *buf, size_t len)
{
	struct tm *gm;
#if defined(HAVE_GMTIME_R)
	struct tm gmbuf;
	gm = gmtime_r(&t, &gmbuf);
#else
	gm = gmtime(&t);
#endif

	if (op_unlikely(gm == NULL))
	{
		op_strlcpy(buf, "", len);
		return buf;
	}

	snprintf(buf, len, "%s %s %d %d -- %02d:%02d:%02d +00:00",
	         ts_names.long_wday[gm->tm_wday],
	         ts_names.long_mon[gm->tm_mon],
	         gm->tm_mday, gm->tm_year + 1900,
	         gm->tm_hour, gm->tm_min, gm->tm_sec);
	return buf;
}

/* -------------------------------------------------------------------------
 * Current time accessors
 * ---------------------------------------------------------------------- */

time_t
op_current_time(void)
{
	return atomic_load_explicit(&op_current_sec, memory_order_relaxed);
}

const struct timeval *
op_current_time_tv(void)
{
	return &op_time;
}

/* -------------------------------------------------------------------------
 * Logging and control callbacks
 * ---------------------------------------------------------------------- */

/*
 * op_log_hook — optional async dispatch hook.
 *
 * When op_start_async_log() is active, this points to op_async_log_enqueue().
 * op_lib_log() calls through this hook instead of calling op_log directly,
 * so log messages go to the async writer thread rather than blocking the
 * calling thread.
 *
 * NULL means synchronous delivery (the default).
 * Written by op_start_async_log() / op_stop_async_log() on the main thread
 * with release ordering; read by op_lib_log() from any thread with acquire.
 */
typedef void (*log_hook_t)(const char *msg);
static _Atomic(log_hook_t) op_log_hook = NULL;

/* Called by op_start_async_log() to install / remove the async hook. */
void
op_lib_set_log_hook(void (*hook)(const char *msg))
{
	atomic_store_explicit((volatile _Atomic(void (*)(const char *)) *)&op_log_hook,
	                      (void (*)(const char *))hook,
	                      memory_order_release);
}

__attribute__((cold))
void
op_lib_log(const char *format, ...)
{
	char errbuf[2048];
	va_list args;

	va_start(args, format);
	vsnprintf(errbuf, sizeof(errbuf), format, args);
	va_end(args);

	/* Fast path: check the async hook first (installed by op_start_async_log). */
	log_hook_t hook = atomic_load_explicit(&op_log_hook, memory_order_acquire);
	if (__builtin_expect(hook != NULL, 0))
	{
		hook(errbuf);
		return;
	}

	/* Synchronous fallback: call the installed log callback directly. */
	log_cb *log = cb_log();
	if (log != NULL)
		log(errbuf);
}

/*
 * op_lib_die — invoke the die callback with a formatted message.
 *
 * If the callback returns (which it should not), we abort() to ensure the
 * process does not continue in an undefined state.  Note: op_lib_die is NOT
 * marked [[noreturn]] in the header because the die_cb signature does not
 * guarantee it; callers that need noreturn semantics should use op_lib_restart.
 */
__attribute__((cold))
void
op_lib_die(const char *format, ...)
{
	die_cb *die = cb_die();
	char errbuf[2048];
	va_list args;

	if (die == NULL)
		abort();

	va_start(args, format);
	vsnprintf(errbuf, sizeof(errbuf), format, args);
	va_end(args);
	die(errbuf);

	/* die() should not return — abort() if it does. */
	abort();
}

/*
 * op_lib_restart — invoke the restart callback with a formatted message.
 *
 * Declared [[noreturn]] in op_lib.h.  The restart_cb is expected to terminate
 * the process; abort() is the fallback if it returns.
 */
__attribute__((cold, noreturn))
void
op_lib_restart(const char *format, ...)
{
	restart_cb *restart = cb_restart();
	char errbuf[2048];
	va_list args;

	if (restart == NULL)
		abort();

	va_start(args, format);
	vsnprintf(errbuf, sizeof(errbuf), format, args);
	va_end(args);
	restart(errbuf);
	abort();
}

/* -------------------------------------------------------------------------
 * Clock management
 * ---------------------------------------------------------------------- */

void
op_set_time(void)
{
	struct timeval newtime;

	if (op_unlikely(op_gettimeofday(&newtime, NULL) == -1))
	{
		op_lib_log("Clock Failure (%s)", strerror(errno));
		op_lib_restart("Clock Failure");
	}

	/* Detect and compensate for wall-clock steps backward (e.g. NTP slew). */
	if (newtime.tv_sec < op_time.tv_sec)
		op_set_back_events(op_time.tv_sec - newtime.tv_sec);

	op_time = newtime;
	atomic_store_explicit(&op_current_sec, newtime.tv_sec, memory_order_relaxed);
}

/* -------------------------------------------------------------------------
 * op_lib_version — human-readable library version string.
 *
 * Format: "<product> <version> — <ssl_info>"
 * Example: "ophion 1.71 — opssl 1.0.0"
 * ---------------------------------------------------------------------- */
const char *
op_lib_version(void)
{
	static _Thread_local char version_buf[256];
	const op_build_info_t *bi = op_build_info();
	char ssl_info[192];

	op_get_ssl_info(ssl_info, sizeof(ssl_info));

	snprintf(version_buf, sizeof(version_buf),
	         "%s %s \xe2\x80\x94 %s",   /* em dash (UTF-8: E2 80 94) */
	         bi->product, bi->version, ssl_info);
	return version_buf;
}

/* -------------------------------------------------------------------------
 * op_lib_init — initialise the library subsystems.
 *
 * CRITICAL: callbacks must be installed (with release semantics) BEFORE
 * op_set_time() is called, because op_set_time() may call op_lib_log() and
 * op_lib_restart() if the system clock is unavailable.
 * ---------------------------------------------------------------------- */
void
op_lib_init(log_cb *ilog, restart_cb *irestart, die_cb *idie,
            int closeall, int maxcon,
            size_t dh_size, size_t fd_heap_size)
{
	/* Install callbacks first so op_set_time's error paths can use them. */
	atomic_store_explicit(&op_log,     ilog,     memory_order_release);
	atomic_store_explicit(&op_restart, irestart, memory_order_release);
	atomic_store_explicit(&op_die,     idie,     memory_order_release);

	op_set_time();
	op_event_init();
	op_init_bh();
	op_fdlist_init(closeall, maxcon, fd_heap_size);
	op_init_netio();
	op_init_dlink_nodes(dh_size);
	if (op_io_supports_event())
		op_io_init_event();
}

/* -------------------------------------------------------------------------
 * op_lib_loop_tick — one I/O + timer iteration.
 *
 * timeout_ms behaviour:
 *   -1  block until the next scheduled timer fires
 *    0  non-blocking poll
 *   >0  block for at most this many milliseconds
 *
 * Used by the shim hot-patch path: the shim owns the outer loop and calls
 * this each iteration so it can check for upgrade signals between ticks.
 * ---------------------------------------------------------------------- */
void
op_lib_loop_tick(int timeout_ms)
{
	op_set_time();
	/* Free all per-tick arena allocations from the previous tick. */
	op_arena_reset(op_event_arena());

	if (op_io_supports_event())
	{
		/* The backend owns timer scheduling; timeout_ms is just the max
		 * block duration. */
		op_select((long)timeout_ms);
		return;
	}

	/* Compute how long until the next scheduled event fires. */
	long wait_ms;
	time_t next_ev = op_event_next();

	if (next_ev > 0)
	{
		long until_ms = (long)(next_ev - op_current_time()) * 1000L;

		/* If the event is already overdue, fire with 0 delay.
		 * Clamp to the caller-supplied maximum when non-negative. */
		if (until_ms < 0)
			until_ms = 0;

		wait_ms = (timeout_ms < 0 || until_ms < (long)timeout_ms)
		          ? until_ms : (long)timeout_ms;
	}
	else
	{
		/* No events scheduled; block for the caller-supplied timeout. */
		wait_ms = (timeout_ms < 0) ? -1L : (long)timeout_ms;
	}

	op_select(wait_ms);
	op_event_run();
}

/* -------------------------------------------------------------------------
 * op_lib_loop — run the event loop forever (never returns).
 *
 * delay == 0  compute timeout from the next scheduled event (preferred)
 * delay  > 0  use this fixed poll interval in milliseconds
 * ---------------------------------------------------------------------- */
__attribute__((noreturn))
void
op_lib_loop(long delay)
{
	op_set_time();

	if (op_io_supports_event())
	{
		/* Backend owns scheduling; block indefinitely and let op_select
		 * wake us for both I/O events and timers. */
		for (;;)
		{
			op_arena_reset(op_event_arena());
			op_select(-1);
		}
	}

	for (;;)
	{
		op_arena_reset(op_event_arena());

		long wait_ms;
		if (delay == 0)
		{
			time_t next_ev = op_event_next();
			if (next_ev > 0)
			{
				long until_ms = (long)(next_ev - op_current_time()) * 1000L;
				/* Overdue events should fire without delay, not after 1 s. */
				wait_ms = (until_ms > 0) ? until_ms : 0;
			}
			else
			{
				wait_ms = -1L;  /* no events scheduled; block indefinitely */
			}
		}
		else
		{
			wait_ms = delay;
		}

		op_select(wait_ms);
		op_event_run();
	}
}

/* -------------------------------------------------------------------------
 * op_strtok_r — thread-safe tokeniser.
 * ---------------------------------------------------------------------- */

#ifndef HAVE_STRTOK_R
char *
op_strtok_r(char *s, const char *delim, char **save)
{
	char *token;

	if (s == NULL)
		s = *save;

	s += strspn(s, delim);
	if (*s == '\0')
	{
		*save = s;
		return NULL;
	}

	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)
		*save = token + strlen(token);
	else
	{
		*s    = '\0';
		*save = s + 1;
	}
	return token;
}
#else
char *
op_strtok_r(char *restrict s, const char *restrict delim, char **restrict save)
{
	return strtok_r(s, delim, save);
}
#endif

/* =========================================================================
 * Base64
 *
 * Encoding table uses the standard alphabet (RFC 4648 §4).
 * The reverse table maps every byte 0–255 to its 6-bit value or -1.
 * ====================================================================== */

static const char b64_enc[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char b64_pad = '=';

/* Lookup: byte → 6-bit value, or -1 for non-base64 characters. */
static const signed char b64_dec[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x00 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x10 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 0x20  +  / */
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 0x30  0-9 */
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 0x40  A-O */
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 0x50  P-Z */
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 0x60  a-o */
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 0x70  p-z */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x80 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0x90 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xa0 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xb0 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xc0 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xd0 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xe0 */
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 0xf0 */
};

/* -------------------------------------------------------------------------
 * op_base64_encode — encode binary data as NUL-terminated base64 string.
 *
 * Returns a heap-allocated string (caller must op_free) or NULL on overflow.
 *
 * Allocation: exact size = ceil(len/3)*4 + 1 bytes.
 * The old code used *5 (25% overallocation).  The correct formula is *4+1:
 *   - each 3-byte input group → 4 output chars
 *   - one trailing NUL
 * Overflow guard: (len+2)/3 > (SIZE_MAX-1)/4 catches wrap in the product.
 * ---------------------------------------------------------------------- */
unsigned char *
op_base64_encode(const unsigned char *src, size_t len)
{
	const unsigned char *in = src;
	unsigned char *out, *p;

	if (len > SIZE_MAX - 2 || (len + 2) / 3 > (SIZE_MAX - 1) / 4)
		return NULL;

	/* Exact allocation: ceil(len/3)*4 bytes of base64 + 1 NUL. */
	p = out = op_malloc(((len + 2) / 3) * 4 + 1);

	while (len > 2)
	{
		*p++ = b64_enc[ in[0] >> 2];
		*p++ = b64_enc[(in[0] & 0x03) << 4 | in[1] >> 4];
		*p++ = b64_enc[(in[1] & 0x0f) << 2 | in[2] >> 6];
		*p++ = b64_enc[ in[2] & 0x3f];
		in  += 3;
		len -= 3;
	}

	if (len == 1)
	{
		*p++ = b64_enc[ in[0] >> 2];
		*p++ = b64_enc[(in[0] & 0x03) << 4];
		*p++ = b64_pad;
		*p++ = b64_pad;
	}
	else if (len == 2)
	{
		*p++ = b64_enc[ in[0] >> 2];
		*p++ = b64_enc[(in[0] & 0x03) << 4 | in[1] >> 4];
		*p++ = b64_enc[(in[1] & 0x0f) << 2];
		*p++ = b64_pad;
	}

	*p = '\0';
	return out;
}

/* -------------------------------------------------------------------------
 * op_base64_decode — decode a base64 string into binary.
 *
 * Returns a heap-allocated buffer (caller must op_free).  The buffer is
 * NUL-terminated for convenience (but may contain embedded NULs in the
 * decoded payload).  *out_len is set to the number of decoded bytes.
 * Returns NULL on invalid padding or allocation failure.
 *
 * Non-base64 characters in the input (whitespace, unknown bytes) are skipped
 * per RFC 2045 lenient decoding.  Decoding stops at the first '=' padding
 * character or a NUL in the input.
 * ---------------------------------------------------------------------- */
unsigned char *
op_base64_decode(const unsigned char *src, size_t len, size_t *out_len)
{
	const unsigned char *in = src;
	unsigned char *result;
	size_t i = 0, j = 0;
	int ch = 0;

	/* Maximum decoded output is ceil(len*3/4) ≤ len bytes; len+1 is safe. */
	if (len == SIZE_MAX)
		return NULL;
	result = op_malloc(len + 1);

	while (len-- > 0 && (ch = (unsigned char)*in++) != '\0')
	{
		if (ch == b64_pad)
			break;

		int val = b64_dec[ch];
		if (val < 0)
			continue;  /* skip whitespace and unknown bytes */

		switch (i & 3)
		{
		case 0:
			result[j]  = (unsigned char)(val << 2);
			break;
		case 1:
			result[j++] |= (unsigned char)(val >> 4);
			result[j]    = (unsigned char)((val & 0x0f) << 4);
			break;
		case 2:
			result[j++] |= (unsigned char)(val >> 2);
			result[j]    = (unsigned char)((val & 0x03) << 6);
			break;
		case 3:
			result[j++] |= (unsigned char)val;
			break;
		}
		i++;
	}

	/* Validate padding: i%4 == 1 means we got one base64 digit with no
	 * matching output — that is an encoding error. */
	if (ch == b64_pad && (i & 3) == 1)
	{
		op_free(result);
		return NULL;
	}

	result[j] = '\0';
	*out_len  = j;
	return result;
}

/* -------------------------------------------------------------------------
 * op_base64url_encode — RFC 4648 §5 base64url (- and _ instead of + and /,
 * no '=' padding).
 *
 * Identical to op_base64_encode except:
 *   '+' → '-'
 *   '/' → '_'
 *   '=' padding stripped
 * ---------------------------------------------------------------------- */
unsigned char *
op_base64url_encode(const unsigned char *src, size_t len)
{
	/* Encode with standard base64 first, then patch in place. */
	unsigned char *out = op_base64_encode(src, len);
	if (!out)
		return NULL;

	for (unsigned char *p = out; *p; p++)
	{
		if (*p == '+') *p = '-';
		else if (*p == '/') *p = '_';
		else if (*p == '=') { *p = '\0'; break; }  /* strip padding */
	}
	return out;
}

/* -------------------------------------------------------------------------
 * op_base64url_decode — RFC 4648 §5 base64url decode.
 *
 * Accepts input with or without '=' padding.  Translates '-' → '+' and
 * '_' → '/' then delegates to op_base64_decode.
 * ---------------------------------------------------------------------- */
unsigned char *
op_base64url_decode(const unsigned char *src, size_t len, size_t *out_len)
{
	if (len >= SIZE_MAX - 4)
		return NULL;

	/* Copy and translate to standard base64. */
	unsigned char *buf = op_malloc(len + 4 + 1); /* +4 for padding */
	size_t i;
	for (i = 0; i < len; i++)
	{
		if      (src[i] == '-') buf[i] = '+';
		else if (src[i] == '_') buf[i] = '/';
		else                    buf[i] = src[i];
	}
	/* Re-add '=' padding to make len a multiple of 4. */
	while (i % 4 != 0)
		buf[i++] = '=';
	buf[i] = '\0';

	unsigned char *decoded = op_base64_decode(buf, i, out_len);
	op_free(buf);
	return decoded;
}
