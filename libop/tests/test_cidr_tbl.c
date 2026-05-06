/*
 * test_cidr_tbl.c — unit tests for op_cidr_tbl.
 *
 * Coverage:
 *   [1]  empty table: all lookups return NULL
 *   [2]  IPv4 /32 insert + match-any
 *   [3]  IPv4 /24 insert + match-any for IPs in that subnet
 *   [4]  IPv4 match-any: addresses outside the subnet return NULL
 *   [5]  IPv4 /0 (default route): matches everything
 *   [6]  IPv4 multiple prefixes: match-any returns first (shortest) match
 *   [7]  IPv4 LPM: returns most specific prefix
 *   [8]  IPv4 delete: removed prefix no longer matches
 *   [9]  IPv4 update: op_cidr_set4 on existing prefix returns old val
 *  [10]  IPv6 /128 insert + match-any
 *  [11]  IPv6 /32 subnet match
 *  [12]  op_cidr_match_any_ss: AF_INET and AF_INET6 dispatch
 *  [13]  count4 / count6 / name introspection
 *  [14]  op_cidr_foreach4: enumerates all IPv4 prefixes
 *  [15]  destroy with free_fn
 *  [16]  IPv4 /8 /16 /24 /32 hierarchy: LPM picks correct depth
 *  [17]  typical IRC D-line scenario: 3 banned subnets + clean IPs
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef _WIN32
# include <arpa/inet.h>
# include <netinet/in.h>
#endif

/* ---- helpers ------------------------------------------------------------- */

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)   do { int _before = failures; const char *_sec = (name);
#define END_SECTION     printf("  %-52s %s\n", _sec, \
                               failures == _before ? "pass" : "FAIL"); } while(0)

/* Parse an IPv4 address string into struct in_addr. */
static struct in_addr
ip4(const char *s)
{
    struct in_addr a;
    inet_pton(AF_INET, s, &a);
    return a;
}

/* Parse an IPv6 address string into struct in6_addr. */
static struct in6_addr
ip6(const char *s)
{
    struct in6_addr a;
    inet_pton(AF_INET6, s, &a);
    return a;
}

/* Build a sockaddr_storage for IPv4. */
static struct sockaddr_storage
ss4(const char *s)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    sin->sin_family = AF_INET;
    sin->sin_addr   = ip4(s);
    return ss;
}

/* Build a sockaddr_storage for IPv6. */
static struct sockaddr_storage
ss6(const char *s)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr   = ip6(s);
    return ss;
}

/* ---- foreach tracking ---------------------------------------------------- */

static int    fe_count;
static int    fe_plen_sum;

static bool
fe_count_cb(const struct sockaddr_storage *prefix, int plen,
            void *val, void *ud)
{
    (void)prefix; (void)val; (void)ud;
    fe_count++;
    fe_plen_sum += plen;
    return true;
}

/* ---- destroy tracking ---------------------------------------------------- */

static int destroy_count;

static void
free_cb(void *val, void *ud)
{
    (void)val; (void)ud;
    destroy_count++;
}

/* ---- tests --------------------------------------------------------------- */

static void
test_empty(void)
{
    op_cidr_tbl_t *t = op_cidr_create("empty");

    SECTION("[1] empty table: all lookups return NULL");
    {
        struct in_addr a4 = ip4("1.2.3.4");
        struct in6_addr a6 = ip6("2001:db8::1");
        CHECK(op_cidr_match_any4(t, &a4) == NULL);
        CHECK(op_cidr_match_any6(t, &a6) == NULL);
        CHECK(op_cidr_lpm4(t, &a4) == NULL);
        CHECK(op_cidr_lpm6(t, &a6) == NULL);
        CHECK(op_cidr_count4(t) == 0);
        CHECK(op_cidr_count6(t) == 0);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_ipv4_basic(void)
{
    op_cidr_tbl_t *t = op_cidr_create("v4basic");

    SECTION("[2] IPv4 /32 host route");
    {
        struct in_addr a = ip4("1.2.3.4");
        op_cidr_set4(t, &a, 32, (void *)1, NULL);

        struct in_addr q = ip4("1.2.3.4");
        CHECK((intptr_t)op_cidr_match_any4(t, &q) == 1);

        struct in_addr miss = ip4("1.2.3.5");
        CHECK(op_cidr_match_any4(t, &miss) == NULL);
    }
    END_SECTION;

    SECTION("[3] IPv4 /24 subnet match");
    {
        struct in_addr net = ip4("10.0.1.0");
        op_cidr_set4(t, &net, 24, (void *)100, NULL);

        struct in_addr in1 = ip4("10.0.1.1");
        struct in_addr in2 = ip4("10.0.1.254");
        CHECK((intptr_t)op_cidr_match_any4(t, &in1) == 100);
        CHECK((intptr_t)op_cidr_match_any4(t, &in2) == 100);
    }
    END_SECTION;

    SECTION("[4] IPv4 match-any: addresses outside subnet miss");
    {
        struct in_addr out1 = ip4("10.0.2.1");   /* different /24 */
        struct in_addr out2 = ip4("192.168.1.1");
        CHECK(op_cidr_match_any4(t, &out1) == NULL);
        CHECK(op_cidr_match_any4(t, &out2) == NULL);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_default_route(void)
{
    op_cidr_tbl_t *t = op_cidr_create("defrt");

    SECTION("[5] IPv4 /0 default route matches everything");
    {
        struct in_addr net = ip4("0.0.0.0");
        op_cidr_set4(t, &net, 0, (void *)42, NULL);

        const char *addrs[] = { "1.2.3.4", "192.168.0.1",
                                 "10.0.0.1", "255.255.255.255", "0.0.0.1" };
        for (int i = 0; i < 5; i++)
        {
            struct in_addr q = ip4(addrs[i]);
            CHECK((intptr_t)op_cidr_match_any4(t, &q) == 42);
        }
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_multiple_prefixes(void)
{
    op_cidr_tbl_t *t = op_cidr_create("multi");

    /* /8: 10.0.0.0/8  = id 8
     * /16: 10.1.0.0/16 = id 16
     * /24: 10.1.2.0/24 = id 24
     * /32: 10.1.2.3/32 = id 32 */
    struct in_addr n8  = ip4("10.0.0.0");
    struct in_addr n16 = ip4("10.1.0.0");
    struct in_addr n24 = ip4("10.1.2.0");
    struct in_addr n32 = ip4("10.1.2.3");

    op_cidr_set4(t, &n8,  8,  (void *)8,  NULL);
    op_cidr_set4(t, &n16, 16, (void *)16, NULL);
    op_cidr_set4(t, &n24, 24, (void *)24, NULL);
    op_cidr_set4(t, &n32, 32, (void *)32, NULL);

    SECTION("[6] match-any returns first (shortest/outermost) match");
    {
        /* 10.1.2.3 is covered by all four prefixes.
         * match-any walks root-to-leaf and returns the first hit: /8. */
        struct in_addr q = ip4("10.1.2.3");
        CHECK((intptr_t)op_cidr_match_any4(t, &q) == 8);

        /* 10.1.2.10 is covered by /8, /16, /24 — first hit is /8. */
        struct in_addr q2 = ip4("10.1.2.10");
        CHECK((intptr_t)op_cidr_match_any4(t, &q2) == 8);

        /* 10.2.0.1 only covered by /8. */
        struct in_addr q3 = ip4("10.2.0.1");
        CHECK((intptr_t)op_cidr_match_any4(t, &q3) == 8);

        /* 11.0.0.1 — not covered by any. */
        struct in_addr q4 = ip4("11.0.0.1");
        CHECK(op_cidr_match_any4(t, &q4) == NULL);
    }
    END_SECTION;

    SECTION("[7] LPM returns most specific prefix");
    {
        struct in_addr q32 = ip4("10.1.2.3");
        CHECK((intptr_t)op_cidr_lpm4(t, &q32) == 32);

        struct in_addr q24 = ip4("10.1.2.100");
        CHECK((intptr_t)op_cidr_lpm4(t, &q24) == 24);

        struct in_addr q16 = ip4("10.1.3.1");
        CHECK((intptr_t)op_cidr_lpm4(t, &q16) == 16);

        struct in_addr q8 = ip4("10.200.0.1");
        CHECK((intptr_t)op_cidr_lpm4(t, &q8) == 8);

        struct in_addr qno = ip4("192.0.0.1");
        CHECK(op_cidr_lpm4(t, &qno) == NULL);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_delete(void)
{
    op_cidr_tbl_t *t = op_cidr_create("del");

    SECTION("[8] delete: removed prefix no longer matches");
    {
        struct in_addr net = ip4("192.168.0.0");
        op_cidr_set4(t, &net, 24, (void *)7, NULL);

        struct in_addr q = ip4("192.168.0.1");
        CHECK((intptr_t)op_cidr_match_any4(t, &q) == 7);
        CHECK(op_cidr_count4(t) == 1);

        void *old = op_cidr_del4(t, &net, 24);
        CHECK((intptr_t)old == 7);
        CHECK(op_cidr_match_any4(t, &q) == NULL);
        CHECK(op_cidr_count4(t) == 0);

        /* Delete non-existent: returns NULL */
        CHECK(op_cidr_del4(t, &net, 24) == NULL);
    }
    END_SECTION;

    SECTION("[9] update: op_cidr_set4 on existing returns old val");
    {
        struct in_addr net = ip4("10.0.0.0");
        op_cidr_set4(t, &net, 8, (void *)100, NULL);
        void *old = NULL;
        int r = op_cidr_set4(t, &net, 8, (void *)200, &old);
        CHECK(r == 0);           /* update, not insert */
        CHECK((intptr_t)old == 100);
        struct in_addr q = ip4("10.5.6.7");
        CHECK((intptr_t)op_cidr_match_any4(t, &q) == 200);
        CHECK(op_cidr_count4(t) == 1);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_ipv6(void)
{
    op_cidr_tbl_t *t = op_cidr_create("v6");

    SECTION("[10] IPv6 /128 host route");
    {
        struct in6_addr a = ip6("2001:db8::1");
        op_cidr_set6(t, &a, 128, (void *)64, NULL);

        struct in6_addr q = ip6("2001:db8::1");
        CHECK((intptr_t)op_cidr_match_any6(t, &q) == 64);

        struct in6_addr miss = ip6("2001:db8::2");
        CHECK(op_cidr_match_any6(t, &miss) == NULL);
    }
    END_SECTION;

    SECTION("[11] IPv6 /32 subnet");
    {
        struct in6_addr net = ip6("2001:db8::");
        op_cidr_set6(t, &net, 32, (void *)32, NULL);

        struct in6_addr in1 = ip6("2001:db8::1");
        struct in6_addr in2 = ip6("2001:db8:ffff::");
        CHECK((intptr_t)op_cidr_match_any6(t, &in1) == 32);
        CHECK((intptr_t)op_cidr_match_any6(t, &in2) == 32);

        struct in6_addr out = ip6("2001:db9::");
        CHECK(op_cidr_match_any6(t, &out) == NULL);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_ss(void)
{
    op_cidr_tbl_t *t = op_cidr_create("ss");

    SECTION("[12] op_cidr_match_any_ss: AF_INET and AF_INET6");
    {
        struct in_addr n4 = ip4("10.0.0.0");
        op_cidr_set4(t, &n4, 8, (void *)4, NULL);

        struct in6_addr n6 = ip6("fd00::");
        op_cidr_set6(t, &n6, 8, (void *)6, NULL);

        struct sockaddr_storage s4 = ss4("10.1.2.3");
        struct sockaddr_storage s6 = ss6("fd00::1");
        struct sockaddr_storage s4miss = ss4("11.0.0.1");

        CHECK((intptr_t)op_cidr_match_any_ss(t, &s4)    == 4);
        CHECK((intptr_t)op_cidr_match_any_ss(t, &s6)    == 6);
        CHECK(op_cidr_match_any_ss(t, &s4miss) == NULL);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_introspection(void)
{
    op_cidr_tbl_t *t = op_cidr_create("intro");

    SECTION("[13] count4 / count6 / name");
    {
        struct in_addr n1 = ip4("1.0.0.0");
        struct in_addr n2 = ip4("2.0.0.0");
        struct in6_addr n3 = ip6("2001::");
        op_cidr_set4(t, &n1, 8, (void *)1, NULL);
        op_cidr_set4(t, &n2, 8, (void *)2, NULL);
        op_cidr_set6(t, &n3, 16, (void *)3, NULL);

        CHECK(op_cidr_count4(t) == 2);
        CHECK(op_cidr_count6(t) == 1);
        CHECK(strcmp(op_cidr_name(t), "intro") == 0);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_foreach(void)
{
    op_cidr_tbl_t *t = op_cidr_create("foreach");

    SECTION("[14] op_cidr_foreach4: enumerates all prefixes");
    {
        struct in_addr n1 = ip4("10.0.0.0");
        struct in_addr n2 = ip4("172.16.0.0");
        struct in_addr n3 = ip4("192.168.0.0");
        op_cidr_set4(t, &n1, 8,  (void *)1, NULL);
        op_cidr_set4(t, &n2, 12, (void *)2, NULL);
        op_cidr_set4(t, &n3, 16, (void *)3, NULL);

        fe_count = 0; fe_plen_sum = 0;
        op_cidr_foreach4(t, fe_count_cb, NULL);
        CHECK(fe_count == 3);
        CHECK(fe_plen_sum == 8 + 12 + 16);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_destroy(void)
{
    op_cidr_tbl_t *t = op_cidr_create("dtroy");

    SECTION("[15] destroy with free_fn");
    {
        struct in_addr a = ip4("1.0.0.0");
        op_cidr_set4(t, &a, 8, (void *)1, NULL);
        struct in6_addr b = ip6("::1");
        op_cidr_set6(t, &b, 128, (void *)2, NULL);
        destroy_count = 0;
        op_cidr_destroy(t, free_cb, NULL);
        CHECK(destroy_count == 2);
        t = NULL;
    }
    END_SECTION;
}

static void
test_hierarchy_lpm(void)
{
    op_cidr_tbl_t *t = op_cidr_create("hier");

    SECTION("[16] /8 /16 /24 /32 hierarchy — LPM picks correct depth");
    {
        struct in_addr a8  = ip4("10.0.0.0");
        struct in_addr a16 = ip4("10.10.0.0");
        struct in_addr a24 = ip4("10.10.20.0");
        struct in_addr a32 = ip4("10.10.20.30");

        op_cidr_set4(t, &a8,  8,  (void *)8,  NULL);
        op_cidr_set4(t, &a16, 16, (void *)16, NULL);
        op_cidr_set4(t, &a24, 24, (void *)24, NULL);
        op_cidr_set4(t, &a32, 32, (void *)32, NULL);

        struct in_addr q32 = ip4("10.10.20.30");
        struct in_addr q24 = ip4("10.10.20.1");
        struct in_addr q16 = ip4("10.10.1.1");
        struct in_addr q8  = ip4("10.1.1.1");

        CHECK((intptr_t)op_cidr_lpm4(t, &q32) == 32);
        CHECK((intptr_t)op_cidr_lpm4(t, &q24) == 24);
        CHECK((intptr_t)op_cidr_lpm4(t, &q16) == 16);
        CHECK((intptr_t)op_cidr_lpm4(t, &q8)  == 8);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

static void
test_dline_scenario(void)
{
    op_cidr_tbl_t *t = op_cidr_create("dlines");

    SECTION("[17] IRC D-line scenario");
    {
        /* Three banned subnets, representing a typical IRC abuse scenario. */
        struct in_addr tor_exit = ip4("185.220.101.0");  /* Tor exit /24 */
        struct in_addr vpn_net  = ip4("45.134.0.0");     /* VPN provider /16 */
        struct in_addr bad_host = ip4("1.2.3.4");        /* single spammer /32 */

        op_cidr_set4(t, &tor_exit, 24, (void *)"tor_exit",  NULL);
        op_cidr_set4(t, &vpn_net,  16, (void *)"vpn_net",   NULL);
        op_cidr_set4(t, &bad_host, 32, (void *)"bad_host",  NULL);

        /* IPs that should match */
        struct in_addr in_tor   = ip4("185.220.101.50");
        struct in_addr in_vpn   = ip4("45.134.200.10");
        struct in_addr in_exact = ip4("1.2.3.4");

        CHECK(op_cidr_match_any4(t, &in_tor)   != NULL);
        CHECK(op_cidr_match_any4(t, &in_vpn)   != NULL);
        CHECK(op_cidr_match_any4(t, &in_exact) != NULL);

        /* Clean IPs that should not match */
        struct in_addr clean1 = ip4("8.8.8.8");
        struct in_addr clean2 = ip4("185.220.102.1");  /* different /24 */
        struct in_addr clean3 = ip4("45.135.0.1");     /* different /16 */

        CHECK(op_cidr_match_any4(t, &clean1) == NULL);
        CHECK(op_cidr_match_any4(t, &clean2) == NULL);
        CHECK(op_cidr_match_any4(t, &clean3) == NULL);

        CHECK(op_cidr_count4(t) == 3);
    }
    END_SECTION;

    op_cidr_destroy(t, NULL, NULL);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 256);
    printf("test_cidr_tbl:\n");

    test_empty();
    test_ipv4_basic();
    test_default_route();
    test_multiple_prefixes();
    test_delete();
    test_ipv6();
    test_ss();
    test_introspection();
    test_foreach();
    test_destroy();
    test_hierarchy_lpm();
    test_dline_scenario();

    if (failures == 0)
        printf("  PASS (17 sections)\n");
    else
        printf("  FAIL (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}
