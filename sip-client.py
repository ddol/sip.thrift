#!/usr/bin/env python

import sys
import json

import pyshark
import thrift
import argh
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

sys.path.append('gen-py')
from sip import *
from sip.ttypes import *



def convert(path, host='DEFAULT', indent=None):
    if indent:
        indent = int(indent)
        
    packet_list = []    
    

    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = signalling.Client(protocol)

        cap = pyshark.FileCapture(path)    

        transport.open()

        for packet in cap:
            parsed = extract(packet, host)
            client.send(parsed)
            packet_list.append(parsed)

        transport.close()

        json_output = json.dumps(packet_list, 
                            indent=indent,
                            separators=(',', ':'))

        return json_output
    except Thrift.TException as te:
        print("TException: {}".format(te.message))

def extract(packet, host):
    thrift = {}
    thrift['utc_time'] = packet.sniff_timestamp
    thrift['protocols'] = [l.layer_name for l in packet.layers]
    thrift['capture_host'] = host
    thrift['ip_src'] = packet.ip.src
    thrift['ip_dst'] = packet.ip.dst
    if hasattr(packet, 'sip'):
        thrift['sip_call_id'] = packet.sip.get_field('Call-ID')
        thrift['sip_method'] = packet.sip.get_field('Method')
        thrift['sip_headders'] = packet.sip.get_field('msg_hdr').split(r'\xd\xa')
        sip_att = packet.sip._all_fields
        del sip_att['sip.msg_hdr']
        thrift['sip_attributes'] = sip_att
    
    return thrift 

parser = argh.ArghParser()
parser.add_commands([convert])

if __name__ == '__main__':
    parser.dispatch()
