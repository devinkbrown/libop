/*
 * libop: ophion support library.
 * op_strbuf.h: Dynamic string builder with small-string optimisation.
 *
 * Replaces the common ircd pattern of:
 *
 *   char buf[BUFSIZE];
 *   snprintf(buf, sizeof(buf), "prefix ");
 *   op_snprintf_append(buf, sizeof(buf), "middle %s", arg);
 *   op_snprintf_append(buf, sizeof(buf), " suffix");
 *
 * which silently truncates and requires knowing the maximum size up front.
 *
 * With op_strbuf:
 *
 *   op_strbuf_t sb;
 *   op_strbuf_init(&sb);
 *   op_strbuf_appendf(&sb, "prefix ");
 *   op_strbuf_appendf(&sb, "middle %s", arg);
 *   op_strbuf_appendf(&sb, " suffix");
 *   send_line(op_strbuf_str(&sb));
 *   op_strbuf_free(&sb);
 *
 * Small-string optimisation: strings up to OP_STRBUF_INLINE_CAP bytes live
 * entirely within the op_strbuf_t struct (no heap allocation).  Strings that
 * grow beyond that limit are transparently promoted to a heap buffer.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_strbuf.h directly; include op_lib.h"
#endif

#ifndef LIBOP_STRBUF_H
#define LIBOP_STRBUF_H

/* Inline capacity (bytes, excluding the NUL terminator).
 * Chosen to keep sizeof(op_strbuf_t) at 192 bytes (3 cache lines). */
#define OP_STRBUF_INLINE_CAP  175

/* ---- type ---------------------------------------------------------------- */

typedef struct op_strbuf
{
	char   *ptr;                           /* points to buf[] or heap memory    */
	size_t  len;                           /* current content length (excl NUL) */
	size_t  cap;                           /* allocated capacity  (excl NUL)    */
	char    buf[OP_STRBUF_INLINE_CAP + 1]; /* inline storage                    */
} op_strbuf_t;

/* ---- construction / reset / destruction ---------------------------------- */

/* Initialise a stack-allocated op_strbuf_t.  Must be called before use. */
static inline void
op_strbuf_init(op_strbuf_t *sb)
{
	sb->ptr    = sb->buf;
	sb->len    = 0;
	sb->cap    = OP_STRBUF_INLINE_CAP;
	sb->buf[0] = '\0';
}

/* Reset to empty without freeing heap memory (allows buffer reuse). */
static inline void
op_strbuf_clear(op_strbuf_t *sb)
{
	sb->len    = 0;
	sb->ptr[0] = '\0';
}

/* Free any heap storage and reset the struct to the inline buffer. */
void op_strbuf_free(op_strbuf_t *sb);

/* ---- append -------------------------------------------------------------- */

/*
 * Append exactly len bytes from s.  Does NOT require s to be NUL-terminated.
 * Returns 0 on success, -1 on OOM (fatal in libop — this never returns -1
 * in practice; exposed for testability).
 */
int op_strbuf_append(op_strbuf_t *sb, const char *s, size_t len);

/* Append a NUL-terminated C string. */
static inline int
op_strbuf_append_cstr(op_strbuf_t *sb, const char *s)
{
	return op_strbuf_append(sb, s, strlen(s));
}

/* Append a single character. */
int op_strbuf_appendc(op_strbuf_t *sb, char c);

/* printf-style formatted append.  Growth is automatic. */
int op_strbuf_appendf(op_strbuf_t *sb, const char *fmt, ...) AFP(2, 3);

/* va_list variant (useful when wrapping in your own vararg function). */
int op_strbuf_vappendf(op_strbuf_t *sb, const char *fmt, va_list ap);

/* ---- access -------------------------------------------------------------- */

/* NUL-terminated content pointer (valid until the next mutating call). */
static inline const char *
op_strbuf_str(const op_strbuf_t *sb)
{
	return sb->ptr;
}

/* Current string length (NOT counting the NUL terminator). */
static inline size_t
op_strbuf_len(const op_strbuf_t *sb)
{
	return sb->len;
}

static inline bool
op_strbuf_empty(const op_strbuf_t *sb)
{
	return sb->len == 0;
}

/*
 * op_strbuf_steal — take ownership of the heap buffer (or a heap copy of the
 * inline buffer when the string is small).  The caller must op_free() the
 * returned pointer.  The op_strbuf_t is reset to the inline buffer afterwards.
 */
char *op_strbuf_steal(op_strbuf_t *sb);

/*
 * op_strbuf_truncate — shorten to at most max_len bytes.
 * Safe no-op when len is already <= max_len.
 */
void op_strbuf_truncate(op_strbuf_t *sb, size_t max_len);

/*
 * op_strbuf_ensure — guarantee at least `extra` bytes of free space beyond
 * the current content.  Returns a pointer to the first unused byte.
 * After writing, call op_strbuf_advance() to record how many bytes were used.
 *
 * Useful for callers that produce output directly (read(2), codec functions)
 * without an intermediate copy through vsnprintf.
 */
char *op_strbuf_ensure(op_strbuf_t *sb, size_t extra);

/*
 * op_strbuf_advance — mark n bytes written via op_strbuf_ensure as used.
 * Appends the NUL terminator.  n must not exceed the extra passed to ensure.
 */
void op_strbuf_advance(op_strbuf_t *sb, size_t n);

/*
 * op_strbuf_trim_end — remove all trailing bytes that appear in reject.
 *
 * Example: op_strbuf_trim_end(&sb, "\r\n ") strips trailing CR, LF, and
 * spaces — a common need when consuming IRC/WebSocket protocol lines.
 */
void op_strbuf_trim_end(op_strbuf_t *sb, const char *reject);

/*
 * op_strbuf_join — append n strings from parts[], separated by sep.
 *
 * NULL entries in parts[] are skipped.  sep may be NULL or "" for no
 * separator.
 *
 * Example:
 *   const char *nuh[] = { "nick", "user", "host" };
 *   op_strbuf_join(&sb, nuh, 3, "!");  // "nick!user!host"
 */
void op_strbuf_join(op_strbuf_t *sb, const char * const *parts, size_t n,
                    const char *sep);

/*
 * op_strbuf_repeat — append s repeated count times.
 *
 * Example: op_strbuf_repeat(&sb, "-", 40) — 40 dashes.
 */
void op_strbuf_repeat(op_strbuf_t *sb, const char *s, size_t count);

#endif /* LIBOP_STRBUF_H */
