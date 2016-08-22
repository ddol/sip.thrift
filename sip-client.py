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


def send(path, host='DEFAULT'):
    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = signalling.Client(protocol)
        transport.open()

        def parse(packet):
            client.send(extract(packet, host))

        cap = pyshark.FileCapture(path, keep_packets=False)   
        cap.apply_on_packets(parse)

        transport.close()

    except Thrift.TException as te:
        print("TException: {}".format(te.message))

def extract(cap_packet, host):
    sip_packet = packet(utc_time=cap_packet.sniff_timestamp)
    
    sip_packet.protocols = [l.layer_name for l in cap_packet.layers]
    sip_packet.capture_host = host
    sip_packet.ip_src = cap_packet.ip.src
    sip_packet.ip_dst = cap_packet.ip.dst
    if hasattr(cap_packet, 'sip'):
        sip_packet.sip_call_id = cap_packet.sip.get_field('Call-ID')
        sip_packet.sip_method = cap_packet.sip.get_field('Method')
        sip_packet.sip_headers = cap_packet.sip.get_field('msg_hdr').split(r'\xd\xa')
        sip_att = cap_packet.sip._all_fields
        del sip_att['sip.msg_hdr']
        sip_packet.sip_attributes = sip_att
    
    return sip_packet 

parser = argh.ArghParser()
parser.add_commands([send])

if __name__ == '__main__':
    parser.dispatch()
