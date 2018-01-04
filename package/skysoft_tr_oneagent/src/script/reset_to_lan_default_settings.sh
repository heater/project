#!/bin/sh
# Copyright (C) 2015-2016 skysoft
# author: eric huang

DHCPD_DISABLE="dhcp.lan.ignore"
DHCPD_EXTOPTION="dhcp.lan.dhcp_option"
LAN_IPADDR="network.lan.ipaddr"
LAN_NETMASK="network.lan.netmask"
LAN1_IPADDR="network.lan1.ipaddr"
LAN1_NETMASK="network.lan1.netmask"
LAN2_IPADDR="network.lan2.ipaddr"
LAN2_NETMASK="network.lan2.netmask"
LAN3_IPADDR="network.lan3.ipaddr"
LAN3_NETMASK="network.lan3.netmask"
DHCPD_DOMAIN_IP="dhcp.domain_router.ip"
DHCPD_START="dhcp.lan.start"
DHCPD_END="dhcp.lan.end"
DHCPD_LEASETIME="dhcp.lan.leasetime"
DHCPD_MANUALLEASE="dhcp.@dnsmasq[0].readethers"
DHCPD_DNS="dhcp.lan.dns"
DHCPD_WINSERVER="dhcp.lan.winserver"
AUTH_LOGIN="system.sauth.login"
DHCPD_DOMAIN="dhcp.@dnsmasq[0].domain"

LAN_START_VAL="192.168.1.2"
LAN_END_VAL="192.168.1.254"
LAN_LEASETIME_VAL="168h"
LAN_GATEWAY_VAL="3,192.168.1.1"
LAN_DNS_VAL="6,192.168.1.1"
DEFAULT_DOMAIN_IP_VAL="192.168.1.1"
DEFAULT_DOMAIN_IP_1_VAL="192.168.1.1"
LAN_IP_VAL="192.168.1.1"
LAN_MASK_VAL="255.255.255.0"
LAN1_IP_VAL="192.168.2.1"
LAN1_MASK_VAL="255.255.255.0"
LAN2_IP_VAL="192.168.3.1"
LAN2_MASK_VAL="255.255.255.0"
LAN3_IP_VAL="192.168.4.1"
LAN3_MASK_VAL="255.255.255.0"
PACKAGES="system dhcp network"

ret=""
old_domain="192.168.1.1"

([ -z "$ret" ] && ret=`uci set ${LAN_IPADDR}=${LAN_IP_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN_NETMASK}=${LAN_MASK_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${DHCPD_START}=${LAN_START_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${DHCPD_END}=${LAN_END_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${DHCPD_LEASETIME}=${LAN_LEASETIME_VAL}`) || return 0
([ -z "$ret" ] && (
	ret=`uci delete ${DHCPD_EXTOPTION}`
	[ -z "$ret" ] && ret=`uci add_list ${DHCPD_EXTOPTION}=${LAN_GATEWAY_VAL}` || return 0
	[ -z "$ret" ] && ret=`uci add_list ${DHCPD_EXTOPTION}=${LAN_DNS_VAL}` || return 0 )
	) || return 0 

old_domain=`uci get ${DHCPD_DOMAIN_IP}`
if [ ${old_domain} != "${DEFAULT_DOMAIN_IP_VAL}" ];then
	[ -z "$ret" ] && ret=`uci set ${DHCPD_DOMAIN_IP}=${DEFAULT_DOMAIN_IP_VAL}` || return 0
fi

([ -z "$ret" ] && ret=`uci set ${DHCPD_WINSERVER}=""`) || return 0
([ -z "$ret" ] && ret=`uci set ${DHCPD_MANUALLEASE}="0"`) || return 0
([ -z "$ret" ] && ret=`uci set ${DHCPD_DOMAIN}="lan"`) || return 0 
([ -z "$ret" ] && ret=`uci set ${LAN1_IPADDR}=${LAN1_IP_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN1_NETMASK}=${LAN1_MASK_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN2_IPADDR}=${LAN2_IP_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN2_NETMASK}=${LAN2_MASK_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN3_IPADDR}=${LAN3_IP_VAL}`) || return 0
([ -z "$ret" ] && ret=`uci set ${LAN3_NETMASK}=${LAN3_MASK_VAL}`) || return 0
if [ -z "$ret" ];then
	for i in ${PACKAGES}; do
		uci commit $i
	done
	rm -f /etc/ethers
	cp -f /rom/etc/config/dhcp /etc/config/dhcp
	/etc/init.d/dnsmasq restart
	/etc/init.d/network restart
	return 1
fi

return 0

	
