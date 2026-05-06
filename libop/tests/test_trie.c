/*
 * test_trie.c — unit tests for op_trie_t (ternary search trie).
 */

#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

/* ---- helpers ------------------------------------------------------------- */

/*
 * The 'key' pointer passed to callbacks is valid only for the duration of
 * the callback — it points into the trie's internal enumeration buffer.
 * collect_keys copies it so we can compare after traversal is done.
 */
typedef struct
{
    char   buf[64][128];   /* copies of found key strings */
    size_t n;
    size_t cap;
} key_list_t;

static bool
collect_keys(const char *key, void *val, void *ud)
{
    (void)val;
    key_list_t *kl = ud;
    if (kl->n < kl->cap)
    {
        strncpy(kl->buf[kl->n], key, sizeof(kl->buf[0]) - 1);
        kl->buf[kl->n][sizeof(kl->buf[0]) - 1] = '\0';
        kl->n++;
    }
    return true;
}

static bool
count_cb(const char *key, void *val, void *ud)
{
    (void)key; (void)val;
    (*(size_t *)ud)++;
    return true;
}

static bool
stop_first_cb(const char *key, void *val, void *ud)
{
    (void)key; (void)val;
    (*(size_t *)ud)++;
    return false;
}

static size_t g_freed;
static void free_cb(void *val, void *ud) { (void)val; (void)ud; g_freed++; }


/* ======================================================================== */

int
main(void)
{
    printf("test_trie\n");

    /* [1] create / destroy empty */
    SECTION("create-destroy");
    {
        op_trie_t *t = op_trie_create("test", false);
        CHECK(t != NULL);
        CHECK(op_trie_count(t) == 0);
#undef STRESS_N
        CHECK(strcmp(op_trie_name(t), "test") == 0);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [2] set / get basic */
    SECTION("set-get");
    {
        op_trie_t *t = op_trie_create("t", false);
        CHECK(op_trie_set(t, "foo", (void *)1, NULL) == 1);
        CHECK(op_trie_set(t, "bar", (void *)2, NULL) == 1);
        CHECK(op_trie_set(t, "baz", (void *)3, NULL) == 1);
        CHECK(op_trie_count(t) == 3);

        CHECK(op_trie_get(t, "foo") == (void *)1);
        CHECK(op_trie_get(t, "bar") == (void *)2);
        CHECK(op_trie_get(t, "baz") == (void *)3);
        CHECK(op_trie_get(t, "qux") == NULL);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [3] update existing key — returns 0, old_val set */
    SECTION("update");
    {
        op_trie_t *t = op_trie_create("t", false);
        void *old = NULL;
        op_trie_set(t, "key", (void *)10, NULL);
        int r = op_trie_set(t, "key", (void *)20, &old);
        CHECK(r == 0);
        CHECK(old == (void *)10);
        CHECK(op_trie_get(t, "key") == (void *)20);
        CHECK(op_trie_count(t) == 1);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [4] has */
    SECTION("has");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "present", (void *)1, NULL);
        CHECK( op_trie_has(t, "present"));
        CHECK(!op_trie_has(t, "absent"));
        op_trie_destroy(t, NULL, NULL);
    }

    /* [5] del — found */
    SECTION("del-found");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "hello", (void *)42, NULL);
        void *v = op_trie_del(t, "hello");
        CHECK(v == (void *)42);
        CHECK(op_trie_count(t) == 0);
#undef STRESS_N
        CHECK(!op_trie_has(t, "hello"));
        op_trie_destroy(t, NULL, NULL);
    }

    /* [6] del — not found */
    SECTION("del-not-found");
    {
        op_trie_t *t = op_trie_create("t", false);
        CHECK(op_trie_del(t, "ghost") == NULL);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [7] prefix-sharing keys (foo / foobar / foobaz) */
    SECTION("prefix-sharing");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "foo",    (void *)1, NULL);
        op_trie_set(t, "foobar", (void *)2, NULL);
        op_trie_set(t, "foobaz", (void *)3, NULL);

        CHECK(op_trie_get(t, "foo")    == (void *)1);
        CHECK(op_trie_get(t, "foobar") == (void *)2);
        CHECK(op_trie_get(t, "foobaz") == (void *)3);

        /* Delete "foo" — the others survive */
        op_trie_del(t, "foo");
        CHECK(!op_trie_has(t, "foo"));
        CHECK( op_trie_has(t, "foobar"));
        CHECK( op_trie_has(t, "foobaz"));
        CHECK(op_trie_count(t) == 2);

        op_trie_destroy(t, NULL, NULL);
    }

    /* [8] case-sensitive vs case-insensitive */
    SECTION("case");
    {
        op_trie_t *cs = op_trie_create("cs", false);
        op_trie_t *ci = op_trie_create("ci", true);

        op_trie_set(cs, "Nick", (void *)1, NULL);
        op_trie_set(ci, "Nick", (void *)1, NULL);

        /* Case-sensitive: "nick" != "Nick" */
        CHECK( op_trie_has(cs, "Nick"));
        CHECK(!op_trie_has(cs, "nick"));
        CHECK(!op_trie_has(cs, "NICK"));

        /* Case-insensitive: all variants match */
        CHECK(op_trie_has(ci, "Nick"));
        CHECK(op_trie_has(ci, "nick"));
        CHECK(op_trie_has(ci, "NICK"));
        CHECK(op_trie_get(ci, "NICK") == (void *)1);

        op_trie_destroy(cs, NULL, NULL);
        op_trie_destroy(ci, NULL, NULL);
    }

    /* [9] foreach — lexicographic order */
    SECTION("foreach");
    {
        const char *words[] = { "apple", "banana", "cherry", "date", "elderberry" };
        op_trie_t *t = op_trie_create("t", false);
        for (size_t i = 0; i < 5; i++)
            op_trie_set(t, words[i], (void *)(i + 1), NULL);

        key_list_t kl;
        memset(&kl, 0, sizeof(kl));
        kl.cap = 64;
        op_trie_foreach(t, collect_keys, &kl);
        CHECK(kl.n == 5);
        /* Lexicographic: apple < banana < cherry < date < elderberry */
        CHECK(strcmp(kl.buf[0], "apple")      == 0);
        CHECK(strcmp(kl.buf[1], "banana")     == 0);
        CHECK(strcmp(kl.buf[2], "cherry")     == 0);
        CHECK(strcmp(kl.buf[3], "date")       == 0);
        CHECK(strcmp(kl.buf[4], "elderberry") == 0);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [10] prefix — filter by prefix */
    SECTION("prefix");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "aba",  (void *)1, NULL);
        op_trie_set(t, "abba", (void *)2, NULL);
        op_trie_set(t, "abc",  (void *)3, NULL);
        op_trie_set(t, "xyz",  (void *)4, NULL);

        size_t cnt = 0;
        op_trie_prefix(t, "ab", count_cb, &cnt);
        CHECK(cnt == 3);   /* aba, abba, abc */

        cnt = 0;
        op_trie_prefix(t, "abb", count_cb, &cnt);
        CHECK(cnt == 1);   /* abba */

        cnt = 0;
        op_trie_prefix(t, "z", count_cb, &cnt);
        CHECK(cnt == 0);   /* no match */

        /* empty prefix = all keys */
        cnt = 0;
        op_trie_prefix(t, "", count_cb, &cnt);
        CHECK(cnt == 4);

        op_trie_destroy(t, NULL, NULL);
    }

    /* [11] wildcard '?' and '*' */
    SECTION("wildcard");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "cat",   (void *)1, NULL);
        op_trie_set(t, "car",   (void *)2, NULL);
        op_trie_set(t, "card",  (void *)3, NULL);
        op_trie_set(t, "dog",   (void *)4, NULL);
        op_trie_set(t, "cargo", (void *)5, NULL);

        size_t cnt;

        /* "ca?" matches cat, car (3 chars) */
        cnt = 0;
        op_trie_wildcard(t, "ca?", count_cb, &cnt);
        CHECK(cnt == 2);

        /* "car*" matches car, card, cargo */
        cnt = 0;
        op_trie_wildcard(t, "car*", count_cb, &cnt);
        CHECK(cnt == 3);

        /* "*" matches all */
        cnt = 0;
        op_trie_wildcard(t, "*", count_cb, &cnt);
        CHECK(cnt == 5);

        /* "d?g" matches dog */
        cnt = 0;
        op_trie_wildcard(t, "d?g", count_cb, &cnt);
        CHECK(cnt == 1);

        /* "ca*o" matches cargo */
        cnt = 0;
        op_trie_wildcard(t, "ca*o", count_cb, &cnt);
        CHECK(cnt == 1);

        op_trie_destroy(t, NULL, NULL);
    }

    /* [12] early stop from callback */
    SECTION("early-stop");
    {
        op_trie_t *t = op_trie_create("t", false);
        for (int i = 0; i < 10; i++)
        {
            char buf[16];
            snprintf(buf, sizeof(buf), "key%d", i);
            op_trie_set(t, buf, (void *)(intptr_t)i, NULL);
        }
        size_t cnt = 0;
        op_trie_foreach(t, stop_first_cb, &cnt);
        CHECK(cnt == 1);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [13] destroy calls free_fn */
    SECTION("destroy-free");
    {
        g_freed = 0;
        op_trie_t *t = op_trie_create("t", false);
        for (int i = 0; i < 8; i++)
        {
            char buf[8];
            snprintf(buf, sizeof(buf), "k%d", i);
            op_trie_set(t, buf, (void *)(intptr_t)i, NULL);
        }
        op_trie_destroy(t, free_cb, NULL);
        CHECK(g_freed == 8);
    }

    /* [14] single-char keys */
    SECTION("single-char");
    {
        op_trie_t *t = op_trie_create("t", false);
        op_trie_set(t, "a", (void *)1, NULL);
        op_trie_set(t, "b", (void *)2, NULL);
        op_trie_set(t, "c", (void *)3, NULL);
        CHECK(op_trie_get(t, "a") == (void *)1);
        CHECK(op_trie_get(t, "b") == (void *)2);
        CHECK(op_trie_get(t, "c") == (void *)3);
        CHECK(op_trie_count(t) == 3);
        op_trie_destroy(t, NULL, NULL);
    }

    /* [15] IRC nick table — case-insensitive, prefix autocomplete */
    SECTION("irc-nick-autocomplete");
    {
        op_trie_t *t = op_trie_create("nicks", true);
        const char *nicks[] = {
            "Alice", "AliceBob", "alex", "BERT", "bert2", "carol"
        };
        for (size_t i = 0; i < 6; i++)
            op_trie_set(t, nicks[i], (void *)(i + 1), NULL);
        CHECK(op_trie_count(t) == 6);

        /* "al" prefix should match alice, alicebob, alex (all lower-folded) */
        size_t cnt = 0;
        op_trie_prefix(t, "al", count_cb, &cnt);
        CHECK(cnt == 3);

        /* "bert" prefix matches bert, bert2 */
        cnt = 0;
        op_trie_prefix(t, "bert", count_cb, &cnt);
        CHECK(cnt == 2);

        /* Case-insensitive lookup */
        CHECK(op_trie_has(t, "ALICE"));
        CHECK(op_trie_has(t, "alice"));
        CHECK(op_trie_has(t, "Alice"));

        op_trie_destroy(t, NULL, NULL);
    }

    /* [16] large stress — 500 keys, all lookups succeed */
    SECTION("stress");
    {
#define STRESS_N 500
        op_trie_t *t = op_trie_create("t", false);
        char keys[STRESS_N][16];
        for (size_t i = 0; i < STRESS_N; i++)
        {
            snprintf(keys[i], sizeof(keys[i]), "key_%04zu", i);
            op_trie_set(t, keys[i], (void *)(i + 1), NULL);
        }
        CHECK(op_trie_count(t) == STRESS_N);
        for (size_t i = 0; i < STRESS_N; i++)
            CHECK(op_trie_get(t, keys[i]) == (void *)(i + 1));

        /* Delete all */
        for (size_t i = 0; i < STRESS_N; i++)
            CHECK(op_trie_del(t, keys[i]) == (void *)(i + 1));
        CHECK(op_trie_count(t) == 0);
#undef STRESS_N

        op_trie_destroy(t, NULL, NULL);
    }

    printf("ALL PASS\n");
    return 0;
}
