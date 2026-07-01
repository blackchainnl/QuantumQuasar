package=xproto
$(package)_version=7.0.31
$(package)_download_path=https://xorg.freedesktop.org/releases/individual/proto
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=c6f9747da0bd3a95f86b17fb8dd5e717c8f3ab7f0ece3ba1b247899ec1ef7747
$(package)_patches=silent_xorg_macros_probe.patch

define $(package)_set_vars
$(package)_config_opts=--without-fop --without-xmlto --without-xsltproc --disable-specs
$(package)_config_opts += --disable-dependency-tracking --enable-option-checking
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/silent_xorg_macros_probe.patch && \
  cp -f $(BASEDIR)/config.guess $(BASEDIR)/config.sub . && \
  cp -f /usr/share/automake-*/missing .
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
