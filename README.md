# sip.thrift

A Thrift spec for SIP, with a reference python implementation using `pyshark`.

```
struct packet{
     1:    required double  utc_time,
     2: 	   list<string> protocols,
     3: 			string  capture_host,
     4: 			string  ip_src,
     5: 			string  ip_dst,
    16: 	        string  sip_call_id,
    17: 	        string  sip_method,
    32: 	   list<string> sip_headers,
    33: map<string, string> sip_attributes,
}
```