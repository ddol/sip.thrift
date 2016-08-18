#!/usr/bin/env python

import pyshark
import thrift
import subprocess
import json
import argh
import ConfigParser
import xml.etree.ElementTree as ET

try:
    from html import unescape  # python 3.4+
except ImportError:
    try:
        from html.parser import HTMLParser  # python 3.x (<3.4)
    except ImportError:
        from HTMLParser import HTMLParser  # python 2.x
    unescape = HTMLParser().unescape



Config = ConfigParser.SafeConfigParser()
Config.read('proto.cfg')

def convert(path, kind = 'xml', indent = None):
    
    
    
    #print(file_in)
    if kind == 'xml':
        xml = open(path)
    elif kind =='pcap':
        xml = subprocess.check_output(['tshark', '-T', 'pdml', '-r', path])
        
    if indent:
        indent = int(indent)
        
    return_dict = simplify(xml)
    
    json_output = json.dumps(return_dict, 
                        indent=indent,
                        separators=(',', ':'))

    return json_output

def simplify(xml):
    root = ET.parse(xml)
    packet_list = []
    
    for packet in root.findall('packet'):
        packet_dict = {}
        for proto_ET in packet.findall('proto'):
            proto_name = proto_ET.get('name')
            att_list = []
            att_list.append(ET_out(proto_ET))
            print(proto_name)
            if proto_name in Config.sections():
                if Config.has_option(proto_name, 'recurse') is True:
                    depth = Config.get(proto_name, 'recurse')
                    lists = get_recurse(proto_ET, depth)
                    att_list.extend(lists)
                else:
                    for field_name in Config.options(proto_name):
                        field_ET = proto_ET.find("field[@name='" +
                                                field_name + "']")
                        if field_ET:
                            att_list.append(ET_out(field_ET))
            packet_dict[proto_name] = att_list
        packet_list.append(packet_dict)

    return packet_list

def ET_out(field_ET, att='showname'):
    return field_ET.get(unescape(att))
                
def get_recurse(proto_ET, depth=1):
    return_list = []

    if depth > 1: 
        for subfield_ET in proto_ET.findall('field'):
            print("for subfield: ")
            return_list.extend(get_recurse(subfield_ET, int(depth) - 1))
    elif depth == 1:
        if proto_ET.findall('field').__len__() > 0:
            sub_list = []
            for field_ET in proto_ET.findall('field'):
                sub_list.append(ET_out(field_ET))
            return_list.append({ET_out(proto_ET,'name'): sub_list})
        else:
            return_list.append(ET_out(proto_ET))
    elif depth == 0:
        print('Zero?')
        return_list.append(ET_out(proto_ET))
    else:
        return False
    
    return return_list


parser = argh.ArghParser()
parser.add_commands([convert])

if __name__ == '__main__':
    parser.dispatch()
