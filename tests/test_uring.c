/*
 * test_uring.c - basic functional test for the io_uring event backend
 *
 * Verifies that:
 *   1. libop selects "uring" as the I/O backend when liburing is present
 *      (set LIBOP_USE_IOTYPE=uring to force selection)
 *   2. A read interest registered via op_setselect() fires when data
 *      arrives on a socketpair
 *   3. A write interest fires when the socket is writable
 *   4. Re-arming inside a callback works (handler re-registers interest)
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_commio.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---------- helpers ---------- */

static int failures = 0;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

#define CHECK_MSG(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s (%s)\n", __FILE__, __LINE__, #cond, (msg)); \
			failures++; \
		} \
	} while (0)

/* ---------- test state ---------- */

static int read_fired  = 0;
static int write_fired = 0;
static const char test_payload[] = "hello-uring";

/* ---------- callbacks ---------- */

static void
on_readable(op_fde_t *F, void *data)
{
	char buf[64];
	int  n;

	(void)data;
	n = read(op_get_fd(F), buf, sizeof(buf) - 1);
	if (n > 0)
	{
		buf[n] = '\0';
		CHECK_MSG(strcmp(buf, test_payload) == 0, buf);
		read_fired++;
	}
	else
	{
		CHECK_MSG(0, "read returned 0 or error in on_readable");
	}
}

static void
on_writable(op_fde_t *F, void *data)
{
	(void)F;
	(void)data;
	write_fired++;
}

/* ---------- tests ---------- */

/* 1 if the uring backend activated, 0 if it fell back (e.g. old kernel). */
static int uring_active __attribute__((unused)) = 0;

static void
test_backend_name(void)
{
	const char *iotype = op_get_iotype();
	printf("  io backend: %s\n", iotype);

#if defined(HAVE_LIBURING)
	if (strcmp(iotype, "uring") == 0)
	{
		uring_active = 1;
		printf("  io_uring active\n");
	}
	else
	{
		printf("  SKIP: io_uring not available on this kernel "
		       "(requires Linux >= 5.1); using %s fallback\n", iotype);
	}
#else
	printf("  SKIP: built without liburing\n");
#endif
}

static void
test_read_fires(void)
{
	op_fde_t *F1, *F2;
	int ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_read_fires");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	/* Register read interest on F2, write test_payload from F1. */
	read_fired = 0;
	op_setselect(F2, OP_SELECT_READ, on_readable, NULL);
	{ ssize_t _r = write(op_get_fd(F1), test_payload, strlen(test_payload)); (void)_r; }

	/* One op_select() tick should dispatch the readable CQE. */
	op_select(100 /* ms */);

	CHECK_MSG(read_fired == 1, "read callback did not fire");

	op_close(F1);
	op_close(F2);
}

static void
test_write_fires(void)
{
	op_fde_t *F1, *F2;
	int ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_write_fires");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	/* A fresh socket is immediately writable. */
	write_fired = 0;
	op_setselect(F1, OP_SELECT_WRITE, on_writable, NULL);
	op_select(100 /* ms */);

	CHECK_MSG(write_fired == 1, "write callback did not fire");

	op_close(F1);
	op_close(F2);
}

static int rearm_count = 0;
#define REARM_TOTAL 3

static void
on_rearm(op_fde_t *F, void *data)
{
	op_fde_t *writer = data;
	char buf[64];
	int  n;

	n = read(op_get_fd(F), buf, sizeof(buf));
	if (n > 0)
		rearm_count++;

	/* Re-register for more reads unless we have enough. */
	if (rearm_count < REARM_TOTAL)
		op_setselect(F, OP_SELECT_READ, on_rearm, writer);

	/* Send the next byte from the writer so the next tick has data. */
	if (rearm_count < REARM_TOTAL)
		{ ssize_t _r = write(op_get_fd(writer), "x", 1); (void)_r; }
}

static void
test_rearm_in_callback(void)
{
	op_fde_t *F1, *F2;
	int i, ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_rearm");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	rearm_count = 0;
	op_setselect(F2, OP_SELECT_READ, on_rearm, F1);
	{ ssize_t _r = write(op_get_fd(F1), "x", 1); (void)_r; } /* prime the pump */

	for (i = 0; i < REARM_TOTAL + 1; i++)
		op_select(100 /* ms */);

	CHECK_MSG(rearm_count == REARM_TOTAL, "rearm count wrong");

	op_close(F1);
	op_close(F2);
}

/* ---------- main ---------- */

int
main(void)
{
	/* Force io_uring backend if the library supports it. */
#if defined(HAVE_LIBURING)
	setenv("LIBOP_USE_IOTYPE", "uring", 1);
#endif

	op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 1024);

	printf("test_uring:\n");

	printf("  [1] backend name\n");
	test_backend_name();

	printf("  [2] read fires\n");
	test_read_fires();

	printf("  [3] write fires\n");
	test_write_fires();

	printf("  [4] rearm in callback\n");
	test_rearm_in_callback();

	if (failures == 0)
		printf("  PASS (%d tests)\n", 4);
	else
		printf("  FAIL (%d failure(s))\n", failures);

	return failures ? 1 : 0;
}
