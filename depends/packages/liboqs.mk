package=liboqs
$(package)_version=0.15.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c

# liboqs provides the NIST ML-DSA-44 (FIPS 204) signatures used by Quantum Quasar
# Protocol V4 consensus. Build a static library only, with no external crypto backend
# (liboqs uses its own SHA2/3), and the portable reference implementation so the
# resulting binary uses deterministic generic code paths across target platforms.
define $(package)_set_vars
  $(package)_config_opts := -DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts += -DOQS_BUILD_ONLY_LIB=ON
  $(package)_config_opts += -DOQS_USE_OPENSSL=OFF
  $(package)_config_opts += -DOQS_DIST_BUILD=OFF
  $(package)_config_opts += -DOQS_OPT_TARGET=generic
  $(package)_config_opts += -DOQS_MINIMAL_BUILD=SIG_ml_dsa_44
  $(package)_config_opts += -DCMAKE_BUILD_TYPE=Release
  $(package)_config_opts += -DOQS_BUILD_ONLY_LIB=ON
  # liboqs treats an unknown CMAKE_SYSTEM_PROCESSOR as a security-sensitive
  # unsupported build. Make the supported release targets explicit.
  $(package)_config_opts_x86_64_linux += -DCMAKE_SYSTEM_PROCESSOR=x86_64
  $(package)_config_opts_aarch64_linux += -DCMAKE_SYSTEM_PROCESSOR=aarch64
  $(package)_config_opts_x86_64_mingw32 += -DCMAKE_SYSTEM_PROCESSOR=x86_64
  $(package)_config_opts_x86_64_darwin += -DCMAKE_SYSTEM_PROCESSOR=x86_64
  $(package)_config_opts_aarch64_darwin += -DCMAKE_SYSTEM_PROCESSOR=arm64
endef

define $(package)_config_cmds
  $($(package)_cmake) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share lib/cmake
endef
