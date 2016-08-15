#!/usr/bin/env python

import xmltodict
from subprocess import check_output
import json
import argh
try:
    from io import BytesIO as StringIO
except ImportError:
    from xmltodict import StringIO
    
def _encode(s):
    try:
        return bytes(s, 'ascii')
    except (NameError, TypeError):
        return s
    
def convert(file_in, kind='xml', indent=None):
    #print(file_in)
    if kind == 'xml':
        xml = open(file_in)
    elif kind =='pcap':
        xml = check_output(['tshark', '-T', 'pdml', '-r', file_in])
        
    parsed_dict = xmltodict.parse(xml)
    json_output = json.dumps(parsed_dict, 
                        indent=int(indent),
                        separators=(',', ':'))

    return json_output

parser = argh.ArghParser()
parser.add_commands([convert])

if __name__ == '__main__':
    parser.dispatch()
