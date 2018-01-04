#!/bin/sh
. /usr/share/libubox/jshn.sh
notify_cmd="/oneagent/senducitocli http://127.0.0.1:1234/value/change/group/"
dns_svr_num="Device.DNS.Client.ServerNumberOfEntries"
dns_svr_1="Device.DNS.Client.Server.1.DNSServer"
dns_svr_2="Device.DNS.Client.Server.2.DNSServer"

#echo "=======================dns notify===================" >> /dev/console
old_dns_servers=`cat /tmp/old_dns_servers` 2>/dev/null
Status=`ubus call network.interface.wan status 2>/dev/null`
json_load "${Status:-{}}"
if json_get_type Status ipv4-address && [ "$Status" = array ]; then
	json_select dns-server
	json_get_values dns_servers
	echo "$dns_servers" > /tmp/old_dns_servers 2>/dev/null
fi

dns_num=`echo $dns_servers | sed 's/ /\n/g' | wc -l`
dns1=`echo $dns_servers | awk '{print $1}'`
#echo "new_dns1==[$dns1]" >> /dev/console
dns2=`echo $dns_servers | awk '{print $2}'`
#echo "new_dns2==[$dns2]" >> /dev/console
old_dns_num=`echo $old_dns_servers | sed 's/ /\n/g' | wc -l`
old_dns1=`echo $old_dns_servers | awk '{print $1}'`
#echo "old_dns1==[$old_dns1]" >> /dev/console
old_dns2=`echo $old_dns_servers | awk '{print $2}'`
#echo "old_dns2==[$old_dns2]" >> /dev/console

if [ "$dns_num" != "$old_dns_num" ] && [ "$old_dns_num" != "0" ]; then
	#echo "send notify dns_svr_num=[$dns_svr_num]" >>/dev/console
	$notify_cmd "$dns_svr_num;"
fi

if [ "$dns1" != "$old_dns1" ]; then
	#echo "send notify dns_svr_1=[$dns_svr_1]" >>/dev/console
	$notify_cmd "$dns_svr_1;"
fi
if [ "$dns2" != "$old_dns2" ]; then
	#echo "send notify dns_svr_2=[$dns_svr_2]" >>/dev/console
	$notify_cmd "$dns_svr_2;"
fi
