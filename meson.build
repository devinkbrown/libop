project('libop', 'c',
  version: '1.0.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'b_lto=false',
  ],
  meson_version: '>= 0.60.0',
)

cc = meson.get_compiler('c')
add_project_arguments('-D_GNU_SOURCE', language: 'c')

_datecode_r = run_command('git', 'log', '-1', '--pretty=format:%ct', check: false)
_datecode = _datecode_r.returncode() == 0 ? _datecode_r.stdout().strip() : '0'
add_project_arguments('-DDATECODE=' + _datecode + 'UL', language: 'c')

if get_option('b_ndebug') == 'false' or (get_option('b_ndebug') == 'if-release' and get_option('buildtype') != 'release')
  add_project_arguments('-DOP_LOCK_DEBUG', language: 'c')
endif

if not meson.is_subproject()
  librt_dep = cc.find_library('rt', required: false)
  liburing_dep = dependency('liburing', required: false)
  win32_socket_dep = dependency('', required: false)
  opssl_dep = dependency('opssl', required: false)
else
  if not is_variable('librt_dep')
    librt_dep = cc.find_library('rt', required: false)
  endif
  if not is_variable('liburing_dep')
    liburing_dep = dependency('liburing', required: false)
  endif
  if not is_variable('win32_socket_dep')
    win32_socket_dep = dependency('', required: false)
  endif
  if not is_variable('opssl_dep')
    opssl_dep = dependency('opssl', required: false)
  endif
endif

cdata = configuration_data()

_funcs = [
  ['HAVE_SNPRINTF',        'snprintf',        '#include <stdio.h>'],
  ['HAVE_VSNPRINTF',       'vsnprintf',       '#include <stdio.h>'],
  ['HAVE_SOCKETPAIR',      'socketpair',      '#include <sys/socket.h>'],
  ['HAVE_GETTIMEOFDAY',    'gettimeofday',    '#include <sys/time.h>'],
  ['HAVE_WRITEV',          'writev',          '#include <sys/uio.h>'],
  ['HAVE_SENDMSG',         'sendmsg',         '#include <sys/socket.h>'],
  ['HAVE_GMTIME_R',        'gmtime_r',        '#include <time.h>'],
  ['HAVE_STRTOK_R',        'strtok_r',        '#include <string.h>'],
  ['HAVE_USLEEP',          'usleep',          '#include <unistd.h>'],
  ['HAVE_NANOSLEEP',       'nanosleep',       '#include <time.h>'],
  ['HAVE_CLOCK_NANOSLEEP', 'clock_nanosleep', '#include <time.h>'],
  ['HAVE_POSIX_SPAWN',     'posix_spawn',     '#include <spawn.h>'],
  ['HAVE_GETEXECNAME',     'getexecname',     ''],
  ['HAVE_STRLCAT',         'strlcat',         '#include <string.h>'],
  ['HAVE_STRLCPY',         'strlcpy',         '#include <string.h>'],
  ['HAVE_STRNDUP',         'strndup',         '#include <string.h>'],
  ['HAVE_STRNLEN',         'strnlen',         '#include <string.h>'],
  ['HAVE_STRCASESTR',      'strcasestr',      '#include <string.h>'],
  ['HAVE_STRCASECMP',      'strcasecmp',      '#include <strings.h>'],
  ['HAVE_STRNCASECMP',     'strncasecmp',     '#include <strings.h>'],
  ['HAVE_FSTAT',           'fstat',           '#include <sys/stat.h>'],
  ['HAVE_SIGNALFD',        'signalfd',        '#include <sys/signalfd.h>'],
  ['HAVE_SELECT',          'select',          '#include <sys/select.h>'],
  ['HAVE_POLL',            'poll',            '#include <poll.h>'],
  ['HAVE_KEVENT',          'kevent',          '#include <sys/event.h>'],
  ['HAVE_PORT_CREATE',     'port_create',     '#include <port.h>'],
  ['HAVE_EPOLL_CTL',       'epoll_ctl',       '#include <sys/epoll.h>'],
  ['HAVE_ARC4RANDOM',      'arc4random',      ''],
  ['HAVE_ARC4RANDOM_BUF',  'arc4random_buf',  ''],
  ['HAVE_GETRANDOM',       'getrandom',       '#include <sys/random.h>'],
  ['HAVE_GETENTROPY',      'getentropy',      '#include <unistd.h>'],
  ['HAVE_GETRUSAGE',       'getrusage',       '#include <sys/resource.h>'],
  ['HAVE_TIMERFD_CREATE',  'timerfd_create',  '#include <sys/timerfd.h>'],
  ['HAVE_ACCEPT4',         'accept4',         '#include <sys/socket.h>'],
  ['HAVE_PIPE2',           'pipe2',           '#include <unistd.h>'],
  ['HAVE_CLOCK_GETTIME',   'clock_gettime',   '#include <time.h>'],
]

foreach f : _funcs
  if cc.has_function(f[1], prefix: '#define _GNU_SOURCE\n' + f[2])
    cdata.set(f[0], 1)
  endif
endforeach

if cc.compiles('''
  #include <sys/socket.h>
  int main(void) { int x = SO_NOSIGPIPE; return x; }
''', name: 'SO_NOSIGPIPE')
  cdata.set('HAVE_SO_NOSIGPIPE', 1)
endif

if liburing_dep.found()
  cdata.set('HAVE_LIBURING', 1)
endif

if opssl_dep.found()
  cdata.set('HAVE_OPSSL', 1)
  if host_machine.system() == 'linux' and cc.has_header('linux/tls.h')
    cdata.set('HAVE_KERNEL_TLS', 1)
    if cc.has_header_symbol('linux/tls.h', 'TLS_CIPHER_CHACHA20_POLY1305')
      cdata.set('HAVE_KTLS_CHACHA20', 1)
    endif
  endif
  cdata.set('HAVE_OPSSL_SESSION_EXPORT', 1)
endif

cdata.set_quoted('BRANDING_NAME', meson.project_name())
cdata.set_quoted('BRANDING_VERSION', meson.project_version())

subdir('include')

subdir('src')

libop_dep = declare_dependency(
  include_directories: libop_inc,
  link_with: libop_lib,
)

meson.override_dependency('libop', libop_dep)

if not meson.is_subproject()
  subdir('tests')
endif
