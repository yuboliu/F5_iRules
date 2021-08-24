when RULE_INIT priority 100 {
    set static::outboundv4_debug 1
}
when LB_SELECTED priority 110 {
    if { [class match -- [IP::local_addr] equals pjs_ipsec_vpn] }{
        snatpool snatpool_211.146.16.253
    }
    elseif { [class match -- [IP::local_addr] equals nxy_ipsec_vpn] }{
        snatpool snatpool_211.146.16.252
    }
    elseif { [IP::addr [LB::server addr] equals 211.146.16.254] }{
        snat automap
    }
    elseif { [IP::addr [LB::server addr] equals 223.70.139.94] }{
        snat automap
    }
    elseif { [class match -- [LB::server addr] equals public-dns] }{
        snat automap
    }
    elseif { [class match -- [LB::server addr] equals class_cmcc] }{
        snat automap
    }
    else {
        snat automap
    }
    if { $static::outboundv4_debug }{
        if { [LB::snat] eq "none" }
            { log local0. "#LB_Selected: Snat disabled on [virtual name]" }
        else 
            { log local0. "#LB_Selected: Snat enabled on [virtual name]. Currently set to [LB::snat]"}
    }
}
when SERVER_CONNECTED priority 200 {
    if { $static::outboundv4_debug }{
        set snat_ip [IP::local_addr]
        log local0. "#SNAT: $snat_ip"
        log local0. "#Server_Connected: IP.client_addr:[IP::client_addr] ; IP.local_addr:[IP::local_addr] -> IP.server_addr:[IP::server_addr]"
    }
}