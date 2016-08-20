/* 
 Defines SIP signalling data and transmission
 */

struct ip{
    1: required byte one,
    2: required byte two,
    3: required byte three,
    4: required byte four
}

struct packet{
     1: required double utc_time,
     2: list<string> protocols,
     3: string capture_host,
     4: ip ip_src,
     5: ip ip_dst,
    16: string call_id,
    32: list<string> sip_headers,
    33: map<string, string> sip_attributes,
}

service signalling {
    void echo(),
    oneway void send(1:packet packet)
}

