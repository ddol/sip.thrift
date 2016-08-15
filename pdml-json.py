#!/usr/bin/env python3

import xmltodict
from subprocess import check_output
import json
import argh
import configparser

config = configparser.SafeConfigParser()
config.read('proto.cfg')

def convert(path : 'file to read', kind : 'xml or pcap' = 'xml',
            indent = None):
    #print(file_in)
    if kind == 'xml':
        xml = open(path)
    elif kind =='pcap':
        xml = check_output(['tshark', '-T', 'pdml', '-r', path])
        
    parsed_dict = xmltodict.parse(xml)
    json_output = json.dumps(parsed_dict, 
                        indent=int(indent),
                        separators=(',', ':'))

    return json_output

parser = argh.ArghParser()
parser.add_commands([convert])

if __name__ == '__main__':
    parser.dispatch()
