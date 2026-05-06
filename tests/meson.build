if liburing_dep.found()
  test_uring = executable('test_uring',
    'test_uring.c',
    dependencies: [liburing_dep],
    link_with: libop_lib,
    include_directories: [libop_inc],
    install: false,
  )
  test('uring', test_uring)
endif

test_htab = executable('test_htab',
  'test_htab.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('htab', test_htab)

test_seccomp = executable('test_seccomp',
  'test_seccomp.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('seccomp', test_seccomp)

test_strbuf = executable('test_strbuf',
  'test_strbuf.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('strbuf', test_strbuf)

test_utf8 = executable('test_utf8',
  'test_utf8.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('utf8', test_utf8)

test_bloom = executable('test_bloom',
  'test_bloom.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('bloom', test_bloom)

test_arena = executable('test_arena',
  'test_arena.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('arena', test_arena)

test_ratelimit = executable('test_ratelimit',
  'test_ratelimit.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('ratelimit', test_ratelimit)

test_lru = executable('test_lru',
  'test_lru.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('lru', test_lru)

test_bitset = executable('test_bitset',
  'test_bitset.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('bitset', test_bitset)

test_pqueue = executable('test_pqueue',
  'test_pqueue.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('pqueue', test_pqueue)

test_vec = executable('test_vec',
  'test_vec.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('vec', test_vec)

test_async = executable('test_async',
  'test_async.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('async', test_async)

test_cidr_tbl = executable('test_cidr_tbl',
  'test_cidr_tbl.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('cidr_tbl', test_cidr_tbl)

test_rbt = executable('test_rbt',
  'test_rbt.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('rbt', test_rbt)

test_str_intern = executable('test_str_intern',
  'test_str_intern.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('str_intern', test_str_intern)

test_deque = executable('test_deque',
  'test_deque.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('deque', test_deque)

test_ringbuf = executable('test_ringbuf',
  'test_ringbuf.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('ringbuf', test_ringbuf)

test_itree = executable('test_itree',
  'test_itree.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('itree', test_itree)

test_trie = executable('test_trie',
  'test_trie.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('trie', test_trie)

test_skiplist = executable('test_skiplist',
  'test_skiplist.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('skiplist', test_skiplist)

test_graph = executable('test_graph',
  'test_graph.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('graph', test_graph)

libm = meson.get_compiler('c').find_library('m', required: false)

test_hll = executable('test_hll',
  'test_hll.c',
  link_with: libop_lib,
  dependencies: [libm],
  include_directories: [libop_inc],
  install: false,
)
test('hll', test_hll)

test_wm = executable('test_wm',
  'test_wm.c',
  link_with: libop_lib,
  include_directories: [libop_inc],
  install: false,
)
test('wm', test_wm)
