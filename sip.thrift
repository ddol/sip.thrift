/* 
 Defines SIP signalling data and transmission
 */

struct packet{
     1: required double utc_time,
     2: list<string> protocols,
     3: string host,
    16: optional i32 userID,
    32: list<string> sip_headers,
    33: map<string, string> sip_attributes,
}

service signalling {
    void echo(1:string echo),
    oneway void send(1:packet packet)
}

