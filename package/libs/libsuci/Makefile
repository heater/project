#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libsuci
PKG_VERSION:=0.1
PKG_RELEASE:=1

#PKG_LICENSE:=GPLv2 LGPLv2.1
PKG_LICENSE_FILES:=

PKG_MAINTAINER:=John xue

include $(INCLUDE_DIR)/package.mk

define Package/libsuci
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=uci command api library
endef

define Package/libsuci/description
 This package contains uci commands API 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += $(FPIC)

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		all
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/include/* $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/libsuci.so $(1)/usr/lib/
endef

define Package/libsuci/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libsuci.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libsuci))
