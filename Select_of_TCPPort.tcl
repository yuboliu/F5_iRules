when RULE_INIT priority 10 {
    set static::outboundv4_debug 1
}
when CLIENT_ACCEPTED priority 20 {
    if { [class match -- [TCP::local_port] equals asgw_port] }{
        pool pool_222.35.42.116
    }
    elseif { [TCP::local_port] equals 80 }{
        pool pool_114.255.33.209
    }
    else {
        pool pool_114.255.33.209
    }
}
}
