# Entware package recipe for tunvless — built by the Entware SDK as a feed package
# (.github/workflows/build.yml): CI drops this file, version.mk and the source tarball into a feed
# directory and runs the SDK on it, the same way hoaxisr/firc is packaged.
#
# The binary is the top-level Makefile's out/tunvless, cross-compiled by the SDK toolchain (GCC 8.4,
# glibc 2.27): wolfSSL is built from the bundled third_party/wolfssl and linked in statically,
# glibc dynamically through Entware's /opt/lib loader.

include $(TOPDIR)/rules.mk

include ./version.mk

PKG_NAME:=tunvless
PKG_VERSION:=$(TUNVLESS_VERSION)
PKG_RELEASE:=$(TUNVLESS_RELEASE)
PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=hoaxisr <rosdrey0@gmail.com>
PKG_SOURCE:=tunvless-source.tar.gz
PKG_SOURCE_URL:=file://$(CURDIR)
PKG_HASH:=skip
PKG_MIRROR_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1
PKGARCH:=$(TUNVLESS_TARGET)

include $(INCLUDE_DIR)/package.mk

# ownik/entware-sdk contains the completed target toolchain but drops its completion stamps
# together with generated IPKs, and Entware's package/check removes .built unless the matching
# configured/prepared checks exist too. Restore the stamp chain of the pinned GCC 8.4/glibc 2.27 SDK
# so the package phase can create the libc/libpthread IPKs from staging without rebuilding GCC.
# Taken as is from hoaxisr/firc (tools/ci/entware-package/Makefile): a future SDK with other stamp
# hashes fails visibly here.
TUNVLESS_TOOLCHAIN_DIR:=$(BUILD_DIR)/toolchain
TUNVLESS_TOOLCHAIN_PREPARED:=.prepared_ad8c94d059fbcd3e4fe92dada0211bba_18f1e190c5d53547fed41a3eaa76e9e9
TUNVLESS_TOOLCHAIN_CONFIGURED:=.configured_68b329da9893e34099c7d8ad5cb9c940
$(shell mkdir -p $(TUNVLESS_TOOLCHAIN_DIR) && \
	touch \
		$(TUNVLESS_TOOLCHAIN_DIR)/$(TUNVLESS_TOOLCHAIN_PREPARED)_check \
		$(TUNVLESS_TOOLCHAIN_DIR)/$(TUNVLESS_TOOLCHAIN_PREPARED) \
		$(TUNVLESS_TOOLCHAIN_DIR)/$(TUNVLESS_TOOLCHAIN_CONFIGURED) \
		$(TUNVLESS_TOOLCHAIN_DIR)/.built)

TUNVLESS_DYNAMIC_LINKER:=ld.so.1
ifneq ($(findstring aarch64,$(TUNVLESS_TARGET)),)
TUNVLESS_DYNAMIC_LINKER:=ld-linux-aarch64.so.1
endif

define Package/tunvless
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TUN device with a VLESS outbound
  URL:=https://github.com/hoaxisr/tunvless
  DEPENDS:=+libpthread +ca-bundle
endef

define Package/tunvless/description
 Creates a TUN device and carries its TCP and UDP traffic to a VLESS server:
 Reality, TLS or none; tcp, grpc, xhttp, ws or httpupgrade; Vision; VLESS encryption.
endef

define Package/tunvless/conffiles
/opt/etc/tunvless/tunvless.conf
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_CROSS)ar" \
		CFLAGS="$(TARGET_CFLAGS)" \
		WOLFSSL_SRC=third_party/wolfssl \
		LDFLAGS="$(TARGET_LDFLAGS) \
			-Wl,--dynamic-linker=/opt/lib/$(TUNVLESS_DYNAMIC_LINKER) \
			-Wl,-rpath,/opt/lib"
endef

define Package/tunvless/install
	$(INSTALL_DIR) $(1)/opt/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/out/tunvless $(1)/opt/bin/tunvless
	$(INSTALL_DIR) $(1)/opt/etc/tunvless
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/entware/files/tunvless.conf $(1)/opt/etc/tunvless/tunvless.conf
	$(INSTALL_DIR) $(1)/opt/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/entware/files/S99tunvless $(1)/opt/etc/init.d/S99tunvless
endef

# Stop the tunnel before its binary goes; start it again after an upgrade if it is enabled.
define Package/tunvless/prerm
#!/bin/sh
[ -x /opt/etc/init.d/S99tunvless ] && /opt/etc/init.d/S99tunvless stop
exit 0
endef

define Package/tunvless/postinst
#!/bin/sh
[ -x /opt/etc/init.d/S99tunvless ] && /opt/etc/init.d/S99tunvless restart
exit 0
endef

$(eval $(call BuildPackage,tunvless))
