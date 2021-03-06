##! This script detects scan

module Scan;

export {

	redef enum Notice::Type += {
		AddressScan,
		PortScan,
		};

	const do_analyze_addr_scan = T &redef;
	const do_analyze_port_scan = T &redef;

	const id_addr_scan = "CONNECTION_FAILED_ADDR";
	const id_port_scan = "CONNECTION_FAILED_PORT";

	## Interval at which to watch for the
	## :bro:id:`Scan::conn_failed_(port|addr)_threshold` variable to be crossed.
	## At the end of each interval the counter is reset.
	const conn_failed_addr_interval = 5min &redef;
	const conn_failed_port_interval = 5min &redef;

	const default_addr_scan_threshold = 25 &redef;
	const default_port_scan_threshold = 15 &redef;

	# For address scan
	const suppress_UDP_scan_checks = T &redef;
	const suppress_TCP_scan_checks = F &redef;
	const suppress_ICMP_scan_checks = T &redef;
	

	global addr_scan_thresh_series: vector of count = vector(100, 200, 300);
	global port_scan_thresh_series: vector of count = vector(10, 20, 30);

	#====================Blacklisting/Whitelisting services===============
	# For blacklisting (this wont be checked if 
	# ::analyze_all_services:: = T )
	const analyze_services: set[port] &redef;
	# For whitelisting, set ::analyze_all_services:: = T
	# and define the whitelisted services in ::skip_services::
	const analyze_all_services = T &redef;
	const skip_services: set[port] &redef;

	#====================Blacklisting/Whitelisting hosts===============
	const analyze_hosts: set[addr] &redef;
	const analyze_all_hosts = T &redef;
	const skip_hosts: set[addr] &redef;

	#====================Blacklisting/Whitelisting subnets===============
	const analyze_subnets: set[subnet] &redef;
	const analyze_all_subnets = T &redef;
	const skip_subnets: set[subnet] &redef;


	# Custom threholds based on service for address scan
	const addr_scan_custom_thresholds: table[port] of count &redef;

}

function isFailedConn(c: connection): bool
	{
	# Sr || ( (hR || ShR) && (data not sent in any direction) ) 
	if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
		 (  ((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
		     (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history )) &&
		     !("D" in c$history || "d" in c$history)) )
		return T;
	return F;
	}

function isReverseFailedConn(c: connection): bool
	{
	# reverse scan i.e. conn dest is the scanner
	# sR || ( (Hr || sHr) && (data not sent in any direction) ) 
	if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
		 (  ((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
		     (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history )) &&
		     !("D" in c$history || "d" in c$history)) )
		return T;
	return F;
	}

function addr_scan_predicate(index: Metrics::Index, str: string): bool
	{
	local service = to_port(index$str);
	local host = index$host;

	local transport_layer_proto = get_port_transport_proto(service);
	if ( suppress_UDP_scan_checks && (transport_layer_proto == udp) )
		return F;
	else if ( suppress_TCP_scan_checks && (transport_layer_proto == tcp) )
		return F;
	else if ( suppress_ICMP_scan_checks && (transport_layer_proto == icmp) )
		return F;

	# Blacklisting/whitelisting services
	if ( !analyze_all_services )
		{
		if ( service !in analyze_services )
			return F;			
		}
	else if ( service in skip_services )
		return F;

	# Blacklisting/whitelisting hosts
	if ( !analyze_all_hosts )
		{
		if ( host !in analyze_hosts )
			return F;			
		}
	else if ( host in skip_hosts )
		return F;

	# Blacklisting/whitelisting subnets
	if ( !analyze_all_subnets )
		{
		local host_in_analyze_subnets = F;		
		for ( net in analyze_subnets )
			{
			if ( host in net )
				{
				host_in_analyze_subnets = T;
				break;
				}
			}
		if ( !host_in_analyze_subnets )
			return F;
		}

	# saving this one for last as it requires
	# relatively more processing
	for ( net in skip_subnets )
		{
		if ( index$host in net )
			return F;
		}

	return T;
	}

function port_scan_predicate(index: Metrics::Index, str: string): bool
	{
	local service = to_port(str);
	local host = index$host;

	local transport_layer_proto = get_port_transport_proto(service);
	if ( suppress_UDP_scan_checks && (transport_layer_proto == udp) )
		return F;
	else if ( suppress_TCP_scan_checks && (transport_layer_proto == tcp) )
		return F;
	else if ( suppress_ICMP_scan_checks && (transport_layer_proto == icmp) )
		return F;

	# Blacklisting/whitelisting services
	if ( !analyze_all_services )
		{
		if ( service !in analyze_services )
			return F;			
		}
	else if ( service in skip_services )
		return F;

	# Blacklisting/whitelisting hosts
	if ( !analyze_all_hosts )
		{
		if ( host !in analyze_hosts )
			return F;			
		}
	else if ( host in skip_hosts )
		return F;

	# Blacklisting/whitelisting subnets
	if ( !analyze_all_subnets )
		{
		local host_in_analyze_subnets = F;		
		for ( net in analyze_subnets )
			{
			if ( host in net )
				{
				host_in_analyze_subnets = T;
				break;
				}
			}
		if ( !host_in_analyze_subnets )
			return F;
		}

	# saving this one for last as it requires
	# relatively more processing
	for ( net in skip_subnets )
		{
		if ( index$host in net )
			return F;
		}

	return T;
	}

function check_addr_scan_threshold(index: Metrics::Index, default_thresh: count, 
				val: count ): bool
	{
	local service = to_port(index$str);

	if ( service in addr_scan_custom_thresholds )
		{
		if ( val > addr_scan_custom_thresholds[service] )
			return T;
		}

	else if ( val > default_thresh)
		return T;

	return F;
	}

function check_port_scan_threshold(index: Metrics::Index, default_thresh: count, 
				val: count ): bool
	{
	return T;
	}

function addr_scan_threshold_crossed(index: Metrics::Index, val: count )
	{
	local outbound = Site::is_local_addr(index$host);
	local direction = "InboundScan";
	if (outbound)
		direction = "OutboundScan";

	#print fmt("function: threshold_crossed, val is %d",val);
	NOTICE([$note=AddressScan, $src=index$host,
					$p=to_port(index$str),
					$sub = direction,
					$msg=fmt("%s scanned %d unique hosts on port %s",
						index$host, val, index$str)]);
	}

function port_scan_threshold_crossed(index: Metrics::Index, val: count )
	{
	local outbound = Site::is_local_addr(index$host);
	local direction = "InboundScan";
	if (outbound)
		direction = "OutboundScan";

	#print fmt("function: threshold_crossed, val is %d",val);
	NOTICE([$note=PortScan, $src=index$host,
					$dst=to_addr(index$str),
					$sub = direction,
					$msg=fmt("%s scanned %d unique ports of host %s",
						index$host, val, index$str)]);
	}

function analyze_addr_scan()
	{
	# note=> Addr scan: table [src_ip, port] of set(dst);	
	# Add filters to the metrics so that the metrics framework knows how to
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	Metrics::add_filter(id_addr_scan, [$log=F,
	$pred = addr_scan_predicate,
	$custom_check_threshold = check_addr_scan_threshold,
	$trigger_custom_check_threshold = 1,
	$threshold_crossed = addr_scan_threshold_crossed, 
	$break_interval = conn_failed_addr_interval,
	#$threshold_series = addr_scan_thresh_series,
	$default_threshold = default_addr_scan_threshold]); 
	}

function analyze_port_scan()
	{
	# note=> Port Sweep: table[src_ip, dst_ip] of set(port);
	# Add filters to the metrics so that the metrics framework knows how to
	# determine when it looks like an actual attack and how to respond when
	# thresholds are crossed.
	Metrics::add_filter(id_port_scan, [$log=F,
	$pred = port_scan_predicate,
	#$custom_check_threshold = check_port_scan_threshold,
	#$trigger_custom_check_threshold = 1,
	$threshold_crossed = port_scan_threshold_crossed, 
	$break_interval = conn_failed_port_interval,
	#$threshold_series = port_scan_thresh_series,
	$default_threshold = default_port_scan_threshold]); 
	}

event bro_init() &priority=3
	{
	# Add local networks here to determine scan direction
	# i.e. inbound scan / outbound scan
	#add Site::local_nets[0.0.0.0/16];

	if ( do_analyze_addr_scan )
		analyze_addr_scan();

	if ( do_analyze_port_scan )
		analyze_port_scan();
	}

function endpoint_state_name( num: count): string
	{
	if ( num == 0 )
		return "TCP_INACTIVE";
	else if ( num == 1)
		return "TCP_SYN_SENT";
	else if ( num == 2 )
		return "TCP_SYN_ACK_SENT";
	else if (num == 3 )
		return "TCP_PARTIAL";
	else if ( num == 4 )
		return "TCP_ESTABLISHED";
	else if ( num == 5 )
		return "TCP_CLOSED";
	else if ( num == 6 )
		return "TCP_RESET";

	return "NONE";
	}

## Generated when a SYN-ACK packet is seen in response to a SYN 
## packet during a TCP handshake. The final ACK of the handshake 
## in response to SYN-ACK may or may not occur later, one way to 
## tell is to check the history field of connection to see if the 
## originator sent an ACK, indicated by ‘A’ in the history string.
#event connection_established(c: connection)
#	{
	# Not useful for scan (too early)
#	}

## Generated for a new active TCP connection if Bro did not see 
## the initial handshake. This event is raised when Bro has observed 
## traffic from each endpoint, but the activity did not begin with 
## the usual connection establishment.
#event partial_connection(c: connection)
	#{
	# I am ignoring it. This does not relate to scan
	#}

## Generated when one endpoint of a TCP connection attempted 
## to gracefully close the connection, but the other endpoint 
## is in the TCP_INACTIVE state. This can happen due to split 
## routing, in which Bro only sees one side of a connection.
#event connection_half_finished(c: connection)
#	{
	# Half connections never were "established", so do scan-checking here.
	# I am not taking *f cases of c$history into account. Ask Seth if I should
#	}



## Generated for an unsuccessful connection attempt. This 
## event is raised when an originator unsuccessfully attempted 
## to establish a connection. “Unsuccessful” is defined as at least 
## tcp_attempt_delay seconds having elapsed since the originator 
## first sent a connection establishment packet to the destination 
## without seeing a reply.
event connection_attempt(c: connection)
	{
	local is_reverse_scan = F;
	
	if ( "S" in c$history )
		is_reverse_scan = F;
	else if ( "H" in c$history )
		is_reverse_scan = T;	
	
	local scanner = c$id$orig_h;
	local victim = c$id$resp_h;
	local scanned_port = c$id$resp_p;

	if ( is_reverse_scan )
		{
		scanner = c$id$resp_h;
		victim = c$id$orig_h;
		scanned_port = c$id$orig_p;
		}

	Metrics::add_unique(id_addr_scan,[ $host = scanner, $str = fmt("%s", scanned_port) ], fmt("%s",victim) );
	Metrics::add_unique(id_port_scan,[ $host = scanner, $str = fmt("%s", victim) ], fmt("%s",scanned_port) );
	}

## Generated for a rejected TCP connection. This event 
## is raised when an originator attempted to setup a TCP 
## connection but the responder replied with a RST packet 
## denying it.
event connection_rejected(c: connection)
	{

	local is_reverse_scan = F;
	
	if ( "S" in c$history )
		is_reverse_scan = F;
	else if ( "s" in c$history )
		is_reverse_scan = T;
	
	local scanner = c$id$orig_h;
	local victim = c$id$resp_h;
	local scanned_port = c$id$resp_p;

	if ( is_reverse_scan )
		{
		scanner = c$id$resp_h;
		victim = c$id$orig_h;
		scanned_port = c$id$orig_p;
		}

	Metrics::add_unique(id_addr_scan,[ $host = scanner, $str = fmt("%s", scanned_port) ], fmt("%s",victim) );
	Metrics::add_unique(id_port_scan,[ $host = scanner, $str = fmt("%s", victim) ], fmt("%s",scanned_port) );
	}

## Generated when an endpoint aborted a TCP connection. 
## The event is raised when one endpoint of an *established* 
## TCP connection aborted by sending a RST packet.
event connection_reset(c: connection)
	{
	local is_reverse_scan = F;
	local is_scan = F;

	if (isFailedConn(c))
		{
		is_scan = T;
		is_reverse_scan = F;
		}

	else if (isReverseFailedConn(c))
		{
		is_scan = T;
		is_reverse_scan = T;
		}

	if ( is_scan )
		{
		local scanner = c$id$orig_h;
		local victim = c$id$resp_h;
		local scanned_port = c$id$resp_p;

		if ( is_reverse_scan )
			{
			scanner = c$id$resp_h;
			victim = c$id$orig_h;
			scanned_port = c$id$orig_p;
			}
		Metrics::add_unique(id_addr_scan,[ $host = scanner, $str = fmt("%s", scanned_port) ], fmt("%s",victim) );
		Metrics::add_unique(id_port_scan,[ $host = scanner, $str = fmt("%s", victim) ], fmt("%s",scanned_port) );
		}
	}

## Generated for each still-open connection when Bro terminates.
event connection_pending(c: connection)
	{
	local is_reverse_scan = F;
	local is_scan = F;

	if (isFailedConn(c))
		{
		is_scan = T;
		is_reverse_scan = F;
		}

	else if (isReverseFailedConn(c))
		{
		is_scan = T;
		is_reverse_scan = T;
		}

	if ( is_scan )
		{
		local scanner = c$id$orig_h;
		local victim = c$id$resp_h;
		local scanned_port = c$id$resp_p;

		if ( is_reverse_scan )
			{
			scanner = c$id$resp_h;
			victim = c$id$orig_h;
			scanned_port = c$id$orig_p;
			}
		Metrics::add_unique(id_addr_scan,[ $host = scanner, $str = fmt("%s", scanned_port) ], fmt("%s",victim) );
		Metrics::add_unique(id_port_scan,[ $host = scanner, $str = fmt("%s", victim) ], fmt("%s",scanned_port) );
		}
	}
