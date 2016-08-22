#!/usr/bin/env python
# Osman Yuksel < yuxel {{|AT|}} sonsuzdongu |-| com >

port = 9090

import time
import sys
import json

sys.path.append('gen-py')
from sip import *
from sip.ttypes import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


class SipHandler:
    def time(self):
        timeStamp = time.time()
        return str(timeStamp)

    def send(self, packet):
        print('Packet@{} {}->{} {}'.format(packet.utc_time,
                                    packet.ip_src,
                                    packet.ip_dst,
                                    packet.sip_method
                                ))

handler = SipHandler()

processor = signalling.Processor(handler)
transport = TSocket.TServerSocket(port=port)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)

print("Starting server")
server.serve()