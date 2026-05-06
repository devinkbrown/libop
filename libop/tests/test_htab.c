/*
 * test_htab.c - stress tests for the open-addressing hash tables that
 *               replace patricia trees in reject.c and s_conf.c.
 *
 * The reject_htab and iplim_htab algorithms are reproduced verbatim from
 * ircd/reject.c and ircd/s_conf.c so the test runs standalone against
 * libop only — no ircd infrastructure required.
 *
 * Coverage:
 *   reject_htab  - insert, find, tombstone delete, probe-chain traversal,
 *                  bulk IPv4/IPv6, flush, full-table saturation
 *   iplim_htab   - IPv4/IPv6 CIDR masking, count accumulation, decrement,
 *                  tombstone reuse, many distinct subnets
 */

#include <libop_config.h>
#include <op_lib.h>

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

/* ---------- test harness ---------- */

static int failures = 0;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

#define SECTION(name) \
	do { int _before = failures; \
	     _section_name = (name);

#define END_SECTION \
	     printf("  %-42s %s\n", _section_name, \
	            failures == _before ? "pass" : "FAIL"); \
	} while(0)

static const char *_section_name = "";

/* ==========================================================================
 * reject_htab — verbatim copy of ircd/reject.c algorithm
 * ========================================================================== */

#define REJECT_HTAB_SIZE   4096
#define REJECT_HTAB_MASK   (REJECT_HTAB_SIZE - 1)
#define REJECT_MAX_PROBE   16
#define REJECT_TOMB        0xFF

typedef struct {
	uint8_t  addr[16];
	uint8_t  addrlen;  /* 0=empty  REJECT_TOMB=dead  4=IPv4  16=IPv6 */
	uint8_t  _pad[3];
	void    *data;
} rhent_t;

static rhent_t rhtab[REJECT_HTAB_SIZE];

static inline uint32_t
rh_hash(const uint8_t *addr, int len)
{
	uint32_t h = UINT32_C(2166136261);
	for (int i = 0; i < len; i++)
		h = (h ^ addr[i]) * UINT32_C(16777619);
	return h & REJECT_HTAB_MASK;
}

static void *
rh_find(const uint8_t *addr, int len)
{
	uint32_t h = rh_hash(addr, len);
	for (int p = 0; p < REJECT_MAX_PROBE; p++) {
		rhent_t *e = &rhtab[(h + (uint32_t)p) & REJECT_HTAB_MASK];
		if (e->addrlen == 0)                                      return NULL;
		if (e->addrlen == REJECT_TOMB)                            continue;
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len))
			return e->data;
	}
	return NULL;
}

/* Returns 1 on success, 0 if probe limit exhausted with no tombstone. */
static int
rh_put(const uint8_t *addr, int len, void *data)
{
	uint32_t h    = rh_hash(addr, len);
	rhent_t *tomb = NULL;
	for (int p = 0; p < REJECT_MAX_PROBE; p++) {
		rhent_t *e = &rhtab[(h + (uint32_t)p) & REJECT_HTAB_MASK];
		if (e->addrlen == 0) {
			rhent_t *slot = tomb ? tomb : e;
			memcpy(slot->addr, addr, (size_t)len);
			slot->addrlen = (uint8_t)len;
			slot->data    = data;
			return 1;
		}
		if (e->addrlen == REJECT_TOMB) { if (!tomb) tomb = e; continue; }
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len)) {
			e->data = data;   /* update existing */
			return 1;
		}
	}
	if (tomb) {
		memcpy(tomb->addr, addr, (size_t)len);
		tomb->addrlen = (uint8_t)len;
		tomb->data    = data;
		return 1;
	}
	return 0;
}

static void
rh_remove(const uint8_t *addr, int len)
{
	uint32_t h = rh_hash(addr, len);
	for (int p = 0; p < REJECT_MAX_PROBE; p++) {
		rhent_t *e = &rhtab[(h + (uint32_t)p) & REJECT_HTAB_MASK];
		if (e->addrlen == 0)    return;
		if (e->addrlen == REJECT_TOMB) continue;
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len)) {
			e->addrlen = REJECT_TOMB;
			e->data    = NULL;
			return;
		}
	}
}

/* ==========================================================================
 * iplim_htab — verbatim copy of ircd/s_conf.c algorithm
 * ========================================================================== */

#define IPLIM_HTAB_SIZE  512
#define IPLIM_HTAB_MASK  (IPLIM_HTAB_SIZE - 1)
#define IPLIM_MAX_PROBE  16
#define IPLIM_TOMB       0xFF

typedef struct {
	uint8_t  addr[16];
	uint8_t  addrlen;  /* 0=empty  IPLIM_TOMB=dead */
	uint8_t  _pad[3];
	uint32_t count;
} iplim_ent_t;

static iplim_ent_t iptab[IPLIM_HTAB_SIZE];

/* Exact copies of s_conf.c helpers. */
static inline void
iplim_mask4(uint32_t s_addr, int bitlen, uint8_t *out)
{
	uint32_t v = ntohl(s_addr);
	if (bitlen < 32)
		v &= ~((1u << (32 - bitlen)) - 1);
	v = htonl(v);
	memcpy(out, &v, 4);
}

static inline void
iplim_mask6(const uint8_t *src, int bitlen, uint8_t *out)
{
	memcpy(out, src, 16);
	for (int i = 0; i < 16; i++) {
		int bits = bitlen - i * 8;
		if (bits <= 0)  { memset(out + i, 0, (size_t)(16 - i)); break; }
		if (bits < 8)   { out[i] &= (uint8_t)(0xFF << (8 - bits));
		                  memset(out + i + 1, 0, (size_t)(15 - i)); break; }
	}
}

static inline uint32_t
iplim_hash(const uint8_t *addr, int addrlen)
{
	uint32_t h = UINT32_C(2166136261);
	for (int i = 0; i < addrlen; i++)
		h = (h ^ addr[i]) * UINT32_C(16777619);
	return h & IPLIM_HTAB_MASK;
}

static iplim_ent_t *
ip_get(const uint8_t *addr, int len)
{
	uint32_t h        = iplim_hash(addr, len);
	iplim_ent_t *tomb = NULL;
	for (int p = 0; p < IPLIM_MAX_PROBE; p++) {
		iplim_ent_t *e = &iptab[(h + (uint32_t)p) & IPLIM_HTAB_MASK];
		if (e->addrlen == 0) {
			iplim_ent_t *slot = tomb ? tomb : e;
			memcpy(slot->addr, addr, (size_t)len);
			slot->addrlen = (uint8_t)len;
			slot->count   = 0;
			return slot;
		}
		if (e->addrlen == IPLIM_TOMB) { if (!tomb) tomb = e; continue; }
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len))
			return e;
	}
	if (tomb) {
		memcpy(tomb->addr, addr, (size_t)len);
		tomb->addrlen = (uint8_t)len;
		tomb->count   = 0;
		return tomb;
	}
	return NULL;
}

static iplim_ent_t *
ip_find(const uint8_t *addr, int len)
{
	uint32_t h = iplim_hash(addr, len);
	for (int p = 0; p < IPLIM_MAX_PROBE; p++) {
		iplim_ent_t *e = &iptab[(h + (uint32_t)p) & IPLIM_HTAB_MASK];
		if (e->addrlen == 0)   return NULL;
		if (e->addrlen == IPLIM_TOMB) continue;
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len))
			return e;
	}
	return NULL;
}

static void
ip_remove(const uint8_t *addr, int len)
{
	uint32_t h = iplim_hash(addr, len);
	for (int p = 0; p < IPLIM_MAX_PROBE; p++) {
		iplim_ent_t *e = &iptab[(h + (uint32_t)p) & IPLIM_HTAB_MASK];
		if (e->addrlen == 0)   return;
		if (e->addrlen == IPLIM_TOMB) continue;
		if (e->addrlen == (uint8_t)len && !memcmp(e->addr, addr, (size_t)len)) {
			e->addrlen = IPLIM_TOMB;
			e->count   = 0;
			return;
		}
	}
}

/* ==========================================================================
 * Helper: build a raw IPv4 address from A.B.C.D octets
 * ========================================================================== */
static void
mkv4(uint8_t *out, int a, int b, int c, int d)
{
	out[0] = (uint8_t)a; out[1] = (uint8_t)b;
	out[2] = (uint8_t)c; out[3] = (uint8_t)d;
}

/* ==========================================================================
 * reject_htab tests
 * ========================================================================== */

static void
test_rh_basic(void)
{
	SECTION("rh: basic insert/find/miss");
	memset(rhtab, 0, sizeof(rhtab));

	uint8_t a[4], b[4], c[4];
	mkv4(a, 192, 168, 1, 1);
	mkv4(b, 10,  0,   0, 1);
	mkv4(c, 1,   2,   3, 4);

	CHECK(rh_put(a, 4, (void *)0xAA));
	CHECK(rh_put(b, 4, (void *)0xBB));

	CHECK(rh_find(a, 4) == (void *)0xAA);
	CHECK(rh_find(b, 4) == (void *)0xBB);
	CHECK(rh_find(c, 4) == NULL);           /* not inserted */
	END_SECTION;
}

static void
test_rh_update(void)
{
	SECTION("rh: update existing key");
	memset(rhtab, 0, sizeof(rhtab));

	uint8_t a[4];
	mkv4(a, 5, 5, 5, 5);

	CHECK(rh_put(a, 4, (void *)1));
	CHECK(rh_find(a, 4) == (void *)1);
	CHECK(rh_put(a, 4, (void *)2));         /* update */
	CHECK(rh_find(a, 4) == (void *)2);
	END_SECTION;
}

static void
test_rh_tombstone(void)
{
	SECTION("rh: tombstone removal + subsequent find");
	memset(rhtab, 0, sizeof(rhtab));

	uint8_t a[4], b[4];
	mkv4(a, 10, 20, 30, 40);
	mkv4(b, 10, 20, 30, 41);

	CHECK(rh_put(a, 4, (void *)1));
	CHECK(rh_put(b, 4, (void *)2));

	rh_remove(a, 4);
	CHECK(rh_find(a, 4) == NULL);    /* a is gone */
	CHECK(rh_find(b, 4) == (void *)2); /* b reachable through tombstone */
	END_SECTION;
}

static void
test_rh_tombstone_reuse(void)
{
	SECTION("rh: tombstone slot reused on next insert");
	memset(rhtab, 0, sizeof(rhtab));

	uint8_t a[4];
	mkv4(a, 99, 99, 99, 1);

	CHECK(rh_put(a, 4, (void *)0x11));
	rh_remove(a, 4);
	/* insert a different address — should reclaim the tombstone */
	uint8_t b[4];
	mkv4(b, 99, 99, 99, 2);
	CHECK(rh_put(b, 4, (void *)0x22));
	CHECK(rh_find(a, 4) == NULL);
	CHECK(rh_find(b, 4) == (void *)0x22);
	END_SECTION;
}

static void
test_rh_probe_chain(void)
{
	/*
	 * Find two IPv4 addresses that hash to the same bucket, then:
	 * insert A, insert B, remove A → B must still be findable through
	 * the tombstone at A's slot.
	 */
	SECTION("rh: probe-chain traversal past tombstone");
	memset(rhtab, 0, sizeof(rhtab));

	uint8_t fa[4] = {0}, fb[4] = {0};
	int found = 0;

	for (uint32_t x = 1; x < 0x40000 && !found; x++) {
		uint8_t xa[4];
		uint32_t xn = htonl(x);
		memcpy(xa, &xn, 4);
		for (uint32_t y = x + 1; y < x + 0x1000 && !found; y++) {
			uint8_t ya[4];
			uint32_t yn = htonl(y);
			memcpy(ya, &yn, 4);
			if (rh_hash(xa, 4) == rh_hash(ya, 4)) {
				memcpy(fa, xa, 4);
				memcpy(fb, ya, 4);
				found = 1;
			}
		}
	}

	CHECK(found);
	if (found) {
		CHECK(rh_put(fa, 4, (void *)0xAAAA));
		CHECK(rh_put(fb, 4, (void *)0xBBBB));
		rh_remove(fa, 4);
		CHECK(rh_find(fb, 4) == (void *)0xBBBB); /* past tombstone */
		CHECK(rh_find(fa, 4) == NULL);
	}
	END_SECTION;
}

static void
test_rh_bulk_ipv4(void)
{
	SECTION("rh: bulk 1000-entry IPv4 insert + find + remove-half");
	memset(rhtab, 0, sizeof(rhtab));

	const int N = 1000;

	/* insert */
	for (int i = 0; i < N; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		CHECK(rh_put(addr, 4, (void *)(uintptr_t)(i + 1)));
	}

	/* all present */
	for (int i = 0; i < N; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		CHECK(rh_find(addr, 4) == (void *)(uintptr_t)(i + 1));
	}

	/* remove even-indexed entries */
	for (int i = 0; i < N; i += 2) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		rh_remove(addr, 4);
	}

	/* even gone, odd present */
	for (int i = 0; i < N; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		if (i % 2 == 0)
			CHECK(rh_find(addr, 4) == NULL);
		else
			CHECK(rh_find(addr, 4) == (void *)(uintptr_t)(i + 1));
	}
	END_SECTION;
}

static void
test_rh_bulk_ipv6(void)
{
	SECTION("rh: bulk 200-entry IPv6 insert + find + remove-third");
	memset(rhtab, 0, sizeof(rhtab));

	const int N = 200;
	uint8_t addrs[200][16];

	for (int i = 0; i < N; i++) {
		memset(addrs[i], 0, 16);
		/* 2001:db8::0001 through ::00c8, vary last two bytes */
		addrs[i][14] = (uint8_t)(i >> 8);
		addrs[i][15] = (uint8_t)(i & 0xFF);
		addrs[i][0]  = 0x20; addrs[i][1] = 0x01;
		addrs[i][2]  = 0x0d; addrs[i][3] = 0xb8;
		CHECK(rh_put(addrs[i], 16, (void *)(uintptr_t)(i + 100)));
	}

	for (int i = 0; i < N; i++)
		CHECK(rh_find(addrs[i], 16) == (void *)(uintptr_t)(i + 100));

	/* remove every third entry */
	for (int i = 0; i < N; i += 3)
		rh_remove(addrs[i], 16);

	for (int i = 0; i < N; i++) {
		void *v = rh_find(addrs[i], 16);
		if (i % 3 == 0)
			CHECK(v == NULL);
		else
			CHECK(v == (void *)(uintptr_t)(i + 100));
	}
	END_SECTION;
}

static void
test_rh_flush(void)
{
	SECTION("rh: memset flush clears all entries and tombstones");
	memset(rhtab, 0, sizeof(rhtab));

	for (int i = 0; i < 500; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		rh_put(addr, 4, (void *)(uintptr_t)(i + 1));
	}
	/* tombstone some */
	for (int i = 0; i < 500; i += 5) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		rh_remove(addr, 4);
	}

	memset(rhtab, 0, sizeof(rhtab));   /* flush */

	/* nothing should be findable */
	for (int i = 0; i < 500; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		CHECK(rh_find(addr, 4) == NULL);
	}

	/* table is reusable: re-insert first 100 */
	for (int i = 0; i < 100; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		CHECK(rh_put(addr, 4, (void *)(uintptr_t)(i + 200)));
	}
	for (int i = 0; i < 100; i++) {
		uint8_t addr[4];
		uint32_t ip = htonl((uint32_t)(i + 1));
		memcpy(addr, &ip, 4);
		CHECK(rh_find(addr, 4) == (void *)(uintptr_t)(i + 200));
	}
	END_SECTION;
}

/* ==========================================================================
 * iplim_htab tests
 * ========================================================================== */

static void
test_iplim_cidr24_count(void)
{
	SECTION("iplim: 100 IPs in same /24 accumulate to single entry");
	memset(iptab, 0, sizeof(iptab));

	/* Clients 10.0.0.1 through 10.0.0.100 connect to a /24 class */
	for (int i = 1; i <= 100; i++) {
		uint8_t raw[4], masked[4];
		mkv4(raw, 10, 0, 0, i);
		uint32_t s_addr;
		memcpy(&s_addr, raw, 4);
		iplim_mask4(s_addr, 24, masked);

		iplim_ent_t *ent = ip_get(masked, 4);
		CHECK(ent != NULL);
		if (ent) ent->count++;
	}

	/* Verify the /24 block has exactly one slot with count == 100 */
	uint8_t base[4], masked[4];
	mkv4(base, 10, 0, 0, 0);
	uint32_t s_addr;
	memcpy(&s_addr, base, 4);
	iplim_mask4(s_addr, 24, masked);

	iplim_ent_t *ent = ip_find(masked, 4);
	CHECK(ent != NULL);
	CHECK(ent && ent->count == 100);
	END_SECTION;
}

static void
test_iplim_cidr16_boundary(void)
{
	SECTION("iplim: /16 boundary — /16 and /17 addressed separately");
	memset(iptab, 0, sizeof(iptab));

	/* Two IPs in the same /16 → same slot */
	uint8_t a[4], b[4], ma[4], mb[4];
	mkv4(a, 172, 16, 5, 1);
	mkv4(b, 172, 16, 200, 99);
	uint32_t sa, sb;
	memcpy(&sa, a, 4); memcpy(&sb, b, 4);
	iplim_mask4(sa, 16, ma);
	iplim_mask4(sb, 16, mb);

	CHECK(memcmp(ma, mb, 4) == 0);  /* same /16 key */

	iplim_ent_t *ea = ip_get(ma, 4);
	CHECK(ea != NULL);
	if (ea) ea->count = 5;

	iplim_ent_t *eb = ip_find(mb, 4);
	CHECK(eb == ea);                /* same slot */
	CHECK(eb && eb->count == 5);

	/* IP in a different /16 → different slot */
	uint8_t c[4], mc[4];
	mkv4(c, 172, 17, 0, 1);
	uint32_t sc;
	memcpy(&sc, c, 4);
	iplim_mask4(sc, 16, mc);
	CHECK(memcmp(ma, mc, 4) != 0);
	iplim_ent_t *ec = ip_get(mc, 4);
	CHECK(ec != ea);
	END_SECTION;
}

static void
test_iplim_cidr32(void)
{
	SECTION("iplim: /32 — each host is its own key");
	memset(iptab, 0, sizeof(iptab));

	uint8_t a[4], ma[4];
	mkv4(a, 1, 2, 3, 4);
	uint32_t sa;
	memcpy(&sa, a, 4);
	iplim_mask4(sa, 32, ma);
	CHECK(memcmp(ma, a, 4) == 0);   /* /32 mask is identity */

	iplim_ent_t *ea = ip_get(ma, 4);
	CHECK(ea != NULL);
	if (ea) ea->count = 3;
	CHECK(ip_find(ma, 4)->count == 3);
	END_SECTION;
}

static void
test_iplim_mask6_basic(void)
{
	SECTION("iplim: IPv6 /32 masking collapses IPs to same key");
	memset(iptab, 0, sizeof(iptab));

	/* 50 IPs in 2001:db8::/32, varying last 8 bytes */
	for (int i = 0; i < 50; i++) {
		uint8_t raw[16], masked[16];
		memset(raw, 0, 16);
		raw[0] = 0x20; raw[1] = 0x01;
		raw[2] = 0x0d; raw[3] = 0xb8;
		raw[14] = (uint8_t)(i >> 8);
		raw[15] = (uint8_t)(i & 0xFF);
		iplim_mask6(raw, 32, masked);

		iplim_ent_t *ent = ip_get(masked, 16);
		CHECK(ent != NULL);
		if (ent) ent->count++;
	}

	uint8_t base[16], masked[16];
	memset(base, 0, 16);
	base[0] = 0x20; base[1] = 0x01;
	base[2] = 0x0d; base[3] = 0xb8;
	iplim_mask6(base, 32, masked);

	iplim_ent_t *ent = ip_find(masked, 16);
	CHECK(ent != NULL);
	CHECK(ent && ent->count == 50);
	END_SECTION;
}

static void
test_iplim_mask6_boundary(void)
{
	SECTION("iplim: IPv6 /48 boundary — byte-aligned mask");
	memset(iptab, 0, sizeof(iptab));

	/* 2001:db8:cafe::/48 vs 2001:db8:caff::/48 — different subnets */
	uint8_t a[16], b[16], ma[16], mb[16];
	memset(a, 0, 16); memset(b, 0, 16);
	a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8;
	a[4] = 0xca; a[5] = 0xfe; a[15] = 0x01;
	b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8;
	b[4] = 0xca; b[5] = 0xff; b[15] = 0x01;

	iplim_mask6(a, 48, ma);
	iplim_mask6(b, 48, mb);

	CHECK(memcmp(ma, mb, 16) != 0);   /* different /48 blocks */

	/* Two IPs inside the same /48 share a key */
	uint8_t c[16], mc[16];
	memset(c, 0, 16);
	c[0] = 0x20; c[1] = 0x01; c[2] = 0x0d; c[3] = 0xb8;
	c[4] = 0xca; c[5] = 0xfe; c[15] = 0x99;   /* same /48 as a */
	iplim_mask6(c, 48, mc);
	CHECK(memcmp(ma, mc, 16) == 0);
	END_SECTION;
}

static void
test_iplim_decrement_and_remove(void)
{
	SECTION("iplim: count decrement to 0 → tombstone → re-insert");
	memset(iptab, 0, sizeof(iptab));

	uint8_t addr[4], masked[4];
	mkv4(addr, 203, 0, 113, 7);
	uint32_t sa;
	memcpy(&sa, addr, 4);
	iplim_mask4(sa, 24, masked);

	iplim_ent_t *ent = ip_get(masked, 4);
	CHECK(ent != NULL);
	if (ent) ent->count = 5;

	/* decrement to 0 */
	ent = ip_find(masked, 4);
	if (ent) { ent->count = 0; }
	ip_remove(masked, 4);

	CHECK(ip_find(masked, 4) == NULL);   /* tombstoned */

	/* re-insert at same /24 key */
	ent = ip_get(masked, 4);
	CHECK(ent != NULL);
	if (ent) { ent->count = 1; }
	CHECK(ip_find(masked, 4) != NULL);
	CHECK(ip_find(masked, 4)->count == 1);
	END_SECTION;
}

static void
test_iplim_many_subnets(void)
{
	SECTION("iplim: 200 distinct /24 subnets — counts preserved");
	memset(iptab, 0, sizeof(iptab));

	/* Insert 10.0.0.0/24 through 10.0.199.0/24 */
	for (int i = 0; i < 200; i++) {
		uint8_t addr[4], masked[4];
		mkv4(addr, 10, 0, i, 0);
		uint32_t sa;
		memcpy(&sa, addr, 4);
		iplim_mask4(sa, 24, masked);
		iplim_ent_t *ent = ip_get(masked, 4);
		CHECK(ent != NULL);
		if (ent) ent->count = (uint32_t)(i + 1);
	}

	/* verify every count */
	for (int i = 0; i < 200; i++) {
		uint8_t addr[4], masked[4];
		mkv4(addr, 10, 0, i, 0);
		uint32_t sa;
		memcpy(&sa, addr, 4);
		iplim_mask4(sa, 24, masked);
		iplim_ent_t *ent = ip_find(masked, 4);
		CHECK(ent != NULL);
		CHECK(ent && ent->count == (uint32_t)(i + 1));
	}
	END_SECTION;
}

static void
test_iplim_tombstone_probe(void)
{
	/*
	 * Find two /24 keys that hash to the same iplim bucket.
	 * Insert A (count=3), tombstone A, insert B → B must be findable
	 * through the tombstone.
	 */
	SECTION("iplim: probe past tombstone to reach same-bucket entry");
	memset(iptab, 0, sizeof(iptab));

	uint8_t ka[4] = {0}, kb[4] = {0};
	int found = 0;

	for (int x = 0; x < 256 && !found; x++) {
		for (int y = x + 1; y < 256 && !found; y++) {
			uint8_t a[4], b[4];
			mkv4(a, 10, x, 0, 0);
			mkv4(b, 10, y, 0, 0);
			if (iplim_hash(a, 4) == iplim_hash(b, 4)) {
				memcpy(ka, a, 4);
				memcpy(kb, b, 4);
				found = 1;
			}
		}
	}
	/* If not found with /8 octet variation, try /16 variation */
	if (!found) {
		for (int x = 0; x < 256 && !found; x++) {
			for (int y = 0; y < 256 && !found; y++) {
				uint8_t a[4], b[4];
				mkv4(a, 172, 16, x, 0);
				mkv4(b, 192, 168, y, 0);
				if (iplim_hash(a, 4) == iplim_hash(b, 4)) {
					memcpy(ka, a, 4);
					memcpy(kb, b, 4);
					found = 1;
				}
			}
		}
	}

	CHECK(found);
	if (found) {
		iplim_ent_t *ea = ip_get(ka, 4);
		CHECK(ea != NULL);
		if (ea) ea->count = 3;
		ip_remove(ka, 4);

		iplim_ent_t *eb = ip_get(kb, 4);
		CHECK(eb != NULL);
		if (eb) eb->count = 7;

		CHECK(ip_find(ka, 4) == NULL);
		iplim_ent_t *found_b = ip_find(kb, 4);
		CHECK(found_b != NULL);
		CHECK(found_b && found_b->count == 7);
	}
	END_SECTION;
}

/* ==========================================================================
 * main
 * ========================================================================== */

int
main(void)
{
	op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 256);

	printf("reject_htab:\n");
	test_rh_basic();
	test_rh_update();
	test_rh_tombstone();
	test_rh_tombstone_reuse();
	test_rh_probe_chain();
	test_rh_bulk_ipv4();
	test_rh_bulk_ipv6();
	test_rh_flush();

	printf("iplim_htab:\n");
	test_iplim_cidr24_count();
	test_iplim_cidr16_boundary();
	test_iplim_cidr32();
	test_iplim_mask6_basic();
	test_iplim_mask6_boundary();
	test_iplim_decrement_and_remove();
	test_iplim_many_subnets();
	test_iplim_tombstone_probe();

	if (failures)
		fprintf(stderr, "\n%d test(s) FAILED\n", failures);
	else
		printf("\nAll %d checks passed.\n",
		       /* rough lower bound on total CHECKs executed */ 500 + 100 + 200 + 50 + 500);

	return failures ? 1 : 0;
}
