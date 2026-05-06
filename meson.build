project('libop', 'c',
  version: '1.0.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ],
  meson_version: '>= 0.60.0',
)

# When used as a subproject, the parent provides these
if not meson.is_subproject()
  # Standalone build needs its own config
  cc = meson.get_compiler('c')
  librt_dep = cc.find_library('rt', required: false)
  liburing_dep = dependency('liburing', required: false)
  win32_socket_dep = dependency('', required: false)
  have_ssl = false
  wolfssl_dep = dependency('', required: false)
else
  # As subproject, these must be set by parent or defaulted
  cc = meson.get_compiler('c')
  if not is_variable('librt_dep')
    librt_dep = cc.find_library('rt', required: false)
  endif
  if not is_variable('liburing_dep')
    liburing_dep = dependency('liburing', required: false)
  endif
  if not is_variable('win32_socket_dep')
    win32_socket_dep = dependency('', required: false)
  endif
  if not is_variable('have_ssl')
    have_ssl = false
  endif
  if not is_variable('wolfssl_dep')
    wolfssl_dep = dependency('', required: false)
  endif
endif

libop_inc = include_directories('include')

subdir('src')

# Declare dependency for consumers
libop_dep = declare_dependency(
  include_directories: libop_inc,
  link_with: libop_lib,
)

meson.override_dependency('libop', libop_dep)

if not meson.is_subproject()
  subdir('tests')
endif
