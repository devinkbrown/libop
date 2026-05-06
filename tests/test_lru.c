/*
 * test_lru.c — unit tests for op_lru LRU cache.
 *
 * Coverage:
 *   - Basic set / get / miss
 *   - LRU eviction: oldest evicted when full
 *   - get promotes entry (changes eviction order)
 *   - Update existing key calls evict_cb with old value
 *   - op_lru_delete
 *   - op_lru_flush
 *   - Stats: hits, misses, evictions, insertions, updates
 *   - op_lru_foreach: MRU-to-LRU order
 *   - Case-insensitive variant (op_lru_create_istr)
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

static int failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

#define SECTION(name)  do { int _before = failures; const char *_sec = (name);
#define END_SECTION    printf("  %-48s %s\n", _sec, failures == _before ? "pass" : "FAIL"); } while (0)

/* ---- eviction tracking --------------------------------------------------- */

static int evict_count = 0;
static char last_evicted_key[64];

static void
on_evict(void *key, void *val, void *ud)
{
    (void)val; (void)ud;
    evict_count++;
    snprintf(last_evicted_key, sizeof(last_evicted_key), "%s", (char *)key);
}

/* ---- tests --------------------------------------------------------------- */

static void
test_basic(void)
{
    SECTION("basic: set / get / miss");
    op_lru_t *c = op_lru_create("test", 4, NULL, NULL);
    CHECK(c != NULL);
    CHECK(op_lru_size(c) == 0);
    CHECK(op_lru_capacity(c) == 4);

    /* Miss on empty cache. */
    CHECK(op_lru_get(c, "key1") == NULL);

    /* Insert and retrieve. */
    op_lru_set(c, "key1", (void *)1UL);
    CHECK(op_lru_get(c, "key1") == (void *)1UL);
    CHECK(op_lru_size(c) == 1);

    /* Another key. */
    op_lru_set(c, "key2", (void *)2UL);
    CHECK(op_lru_get(c, "key2") == (void *)2UL);
    CHECK(op_lru_size(c) == 2);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_eviction_order(void)
{
    SECTION("eviction: oldest key evicted when full");
    evict_count = 0;
    op_lru_t *c = op_lru_create("evict-test", 3, on_evict, NULL);

    /* Insert 3 keys: A, B, C. A is oldest (LRU). */
    op_lru_set(c, "A", (void *)1UL);
    op_lru_set(c, "B", (void *)2UL);
    op_lru_set(c, "C", (void *)3UL);
    CHECK(op_lru_size(c) == 3);

    /* Insert D — A should be evicted. */
    op_lru_set(c, "D", (void *)4UL);
    CHECK(evict_count == 1);
    CHECK(strcmp(last_evicted_key, "A") == 0);
    CHECK(op_lru_get(c, "A") == NULL);
    CHECK(op_lru_get(c, "D") == (void *)4UL);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_get_promotes(void)
{
    SECTION("get: promotes entry — changes eviction order");
    evict_count = 0;
    op_lru_t *c = op_lru_create("promote-test", 3, on_evict, NULL);

    op_lru_set(c, "A", (void *)1UL);
    op_lru_set(c, "B", (void *)2UL);
    op_lru_set(c, "C", (void *)3UL);

    /* Access A — it moves to MRU; B becomes the LRU. */
    CHECK(op_lru_get(c, "A") == (void *)1UL);

    /* Insert D — B should be evicted (not A). */
    op_lru_set(c, "D", (void *)4UL);
    CHECK(evict_count == 1);
    CHECK(strcmp(last_evicted_key, "B") == 0);
    CHECK(op_lru_get(c, "A") != NULL);
    CHECK(op_lru_get(c, "B") == NULL);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_update(void)
{
    SECTION("update: existing key replaces value, evict_cb called with old");
    evict_count = 0;
    op_lru_t *c = op_lru_create("update-test", 4, on_evict, NULL);

    op_lru_set(c, "key", (void *)1UL);
    op_lru_set(c, "key", (void *)2UL);  /* update */

    CHECK(op_lru_get(c, "key") == (void *)2UL);
    CHECK(op_lru_size(c) == 1);         /* no duplicate entry */
    CHECK(evict_count == 1);            /* old value evicted */

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_delete(void)
{
    SECTION("delete: removes entry, evict_cb called");
    evict_count = 0;
    op_lru_t *c = op_lru_create("delete-test", 4, on_evict, NULL);

    op_lru_set(c, "k1", (void *)1UL);
    op_lru_set(c, "k2", (void *)2UL);

    CHECK(op_lru_delete(c, "k1") == true);
    CHECK(evict_count == 1);
    CHECK(op_lru_size(c) == 1);
    CHECK(op_lru_get(c, "k1") == NULL);
    CHECK(op_lru_get(c, "k2") != NULL);

    /* Deleting absent key returns false. */
    CHECK(op_lru_delete(c, "nope") == false);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_flush(void)
{
    SECTION("flush: evicts all entries");
    evict_count = 0;
    op_lru_t *c = op_lru_create("flush-test", 4, on_evict, NULL);

    op_lru_set(c, "a", (void *)1UL);
    op_lru_set(c, "b", (void *)2UL);
    op_lru_set(c, "c", (void *)3UL);

    op_lru_flush(c);
    CHECK(op_lru_size(c) == 0);
    CHECK(evict_count == 3);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_stats(void)
{
    SECTION("stats: hits, misses, evictions, insertions, updates");
    op_lru_t *c = op_lru_create("stats-test", 2, NULL, NULL);

    op_lru_set(c, "a", (void *)1UL);  /* insert */
    op_lru_set(c, "b", (void *)2UL);  /* insert */
    op_lru_get(c, "a");               /* hit */
    op_lru_get(c, "x");               /* miss */
    op_lru_set(c, "a", (void *)9UL);  /* update */
    op_lru_set(c, "c", (void *)3UL);  /* insert + eviction of b */

    op_lru_stats_t s;
    op_lru_stats(c, &s);
    CHECK(s.hits       == 1);
    CHECK(s.misses     == 1);
    CHECK(s.insertions == 3);
    CHECK(s.updates    == 1);
    CHECK(s.evictions  == 1);

    op_lru_destroy(c, false);
    END_SECTION;
}

/* ---- foreach visitor ----------------------------------------------------- */

static int visit_count = 0;
static const char *visit_order[16];

static int
record_visit(const void *key, void *val, void *ud)
{
    (void)val; (void)ud;
    if (visit_count < 16)
        visit_order[visit_count] = (const char *)key;
    visit_count++;
    return 0;
}

static void
test_foreach_order(void)
{
    SECTION("foreach: MRU-to-LRU order");
    visit_count = 0;
    op_lru_t *c = op_lru_create("foreach-test", 4, NULL, NULL);

    op_lru_set(c, "A", (void *)1UL);
    op_lru_set(c, "B", (void *)2UL);
    op_lru_set(c, "C", (void *)3UL);
    /* C is MRU, A is LRU. */

    op_lru_foreach(c, record_visit, NULL);
    CHECK(visit_count == 3);
    CHECK(strcmp(visit_order[0], "C") == 0);
    CHECK(strcmp(visit_order[1], "B") == 0);
    CHECK(strcmp(visit_order[2], "A") == 0);

    op_lru_destroy(c, false);
    END_SECTION;
}

static void
test_istr(void)
{
    SECTION("istr: case-insensitive keys");
    op_lru_t *c = op_lru_create_istr("istr-test", 4, NULL, NULL);

    op_lru_set(c, "Nick", (void *)42UL);
    CHECK(op_lru_get(c, "nick") == (void *)42UL);
    CHECK(op_lru_get(c, "NICK") == (void *)42UL);

    op_lru_destroy(c, false);
    END_SECTION;
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    printf("op_lru tests\n");

    test_basic();
    test_eviction_order();
    test_get_promotes();
    test_update();
    test_delete();
    test_flush();
    test_stats();
    test_foreach_order();
    test_istr();

    printf("\n%s (%d failure%s)\n",
           failures ? "FAIL" : "PASS", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
