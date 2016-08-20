#!/usr/bin/env python

import pyshark
import thrift
import json
import argh

def convert(path, host='DEFAULT', indent=None):
    if indent:
        indent = int(indent)
        
    packet_list = []    
    
    cap = pyshark.FileCapture(path)
    for packet in cap:
        packet_list.append(extract(packet, host))
    
    json_output = json.dumps(packet_list, 
                        indent=indent,
                        separators=(',', ':'))

    return json_output

def extract(packet, host):
    thrift = {}
    thrift['utc_time'] = packet.sniff_timestamp
    thrift['protocols'] = [l.layer_name for l in packet.layers]
    thrift['capture_host'] = host
    thrift['ip_src'] = packet.ip.src
    thrift['ip_dst'] = packet.ip.dst
    thrift['call_id'] = packet.sip.get_field('Call-ID')
    thrift['sip_headders'] = packet.sip.get_field('msg_hdr').split(r'\xd\xa')
    sip_att = packet.sip._all_fields
    del sip_att['sip.msg_hdr']
    thrift['sip_attributes'] = sip_att
    
    return thrift 

parser = argh.ArghParser()
parser.add_commands([convert])

if __name__ == '__main__':
    parser.dispatch()
