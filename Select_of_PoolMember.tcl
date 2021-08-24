when RULE_INIT priority 100 {
    set static::ocss2_debug 0
}
when CLIENT_ACCEPTED priority 110 {
	if { [TCP::local_port] equals 443 } {
		pool pool_192.156.45.23_9081 member 192.156.45.23
		if { $static::ocss2_debug }{
			set cmd "set local_port [TCP::local_port]"
			eval {$cmd}
			log local0. "#Local port is : $local_port"
			}
		}
	elseif { [TCP::local_port] equals 9081 } {
		pool pool_192.156.45.27_9081 member 192.156.45.27
		if { $static::ocss2_debug }{
			log local0. "#Local port is : [TCP::local_port]"
			}
		}
}
when LB_SELECTED priority 120 {
    if { $static::ocss2_debug }{
        if { [LB::snat] eq "none" }
            { log local0. "#LB_Selected: Snat disabled on [virtual name]" }
        else 
            { log local0. "#LB_Selected: Snat enabled on [virtual name]. Currently set to [LB::snat]"}
    }
}
when SERVER_CONNECTED priority 130 {
    if { $static::ocss2_debug }{
        set snat_ip [IP::local_addr]
        log local0. "#SNAT: $snat_ip"
        log local0. "#Server_Connected: IP.client_addr:[IP::client_addr] ; IP.local_addr:[IP::local_addr] -> IP.server_addr:[IP::server_addr]"
    }
}