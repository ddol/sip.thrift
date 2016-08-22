/* 
 Defines SIP signalling data and transmission
 */

struct packet{
     1:    required string  utc_time,
     2: 	   list<string> protocols,
     3: 			string  capture_host,
     4: 			string  ip_src,
     5: 			string  ip_dst,
    16: 	        string  sip_call_id,
    17: 	        string  sip_method,
    32: 	   list<string> sip_headers,
    33: map<string, string> sip_attributes,
}

service signalling {
    string time(),
    oneway void send(1:packet packet)
}

