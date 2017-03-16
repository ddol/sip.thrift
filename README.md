# sip.thrift

A Thrift spec for SIP, with a reference python implementation using `pyshark`.

```
struct packet{
     1: required double               utc_time,
     2: required list<string>         protocols,
     3: required string               capture_host,
     4: required string               ip_src,
     5: required string               ip_dst,
    16: optional string               sip_call_id,
    17: optional string               sip_method,
    32: optional list<string>         sip_headers,
    33: optional map<string,string>   sip_attributes,
}
```
