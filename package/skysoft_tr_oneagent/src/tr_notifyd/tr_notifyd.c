
#include "tr_notifyd.h"
//#include "log.h"

void sigtimeout_handler()
{
	printf("----- timeout now -----\n");
	// Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.
	//check_wireless_client_event();
	// Device.Hosts.Host.{i}.IPv4Address.{i}.
	check_host_event();
	
	check_captive_portal_status();
	// Device.ManagementServer.ManageableDeviceNumberOfEntries
	//check_manageable_device_event();
	// Device.IP.ActivePortNumberOfEntries
	//check_active_port_event();
	// Device.Routing.Router.{i}.IPv4ForwardingNumberOfEntries
	// Device.NAT.PortMappingNumberOfEntries
	// Device.DHCPv4.Client.{i}.DHCPStatus
	//check_dhcp_client_status_event();
	// Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries
	//check_reserved_ip_event();
	// Device.WiFi.Radio.{i}.Channel
}



void display_usage(char *s)
{
	fprintf(stderr, "Usage: %s [-t nseconds] [-d]\n", s);
	exit(EXIT_FAILURE);
}

int  main(int argc, char *argv[])
{
	int debug = DEBUG_LEVEL;
	int interval = 2;
	int opt;
	
	tr_log_init();

	while((opt = getopt(argc, argv, "t:dh")) != -1){
		switch (opt) {
			case 'd':
				debug = 1;
				break;
			case 't':
				interval = atoi(optarg);
				break;
			case 'h':
				display_usage(argv[0]);
				break;
			default :
				display_usage(argv[0]);
				break;
		}
	}

	printf("debug=%d, interval=%d\n", debug, interval);
	printf("argc=%d, optind=%d\n", argc, optind);
	daemon(debug, debug);

	signal(SIGALRM, sigtimeout_handler);	
	
	setup_timer(interval);	

	while(1)
	{
		pause();
	}
	printf("clean timer\n");
	cancel_timer();


	return 0;

}

