ltm rule irules_insert_cer {
    when HTTP_REQUEST priority 100 {
    clientside {
        if { [SSL::cert 0] != ""} {
                set thecert [findstr [X509::whole [SSL::cert 0]] "-----BEGIN CERTIFICATE-----" 28 "-----END CERTIFICATE-----"]
                HTTP::header insert \$WSCC $thecert
#               log local0. "$thecert"
        } 
    }
}
}