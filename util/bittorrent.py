import pyshark
import socket
import os
import re
from pyshark.packet.packet import Packet
from util.AC import *

def strlist_tohexlist(strl: list):
    hexl = []
    for string in strl:
        hexl.append(string.encode().hex())
    return hexl

def gethostip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def gethostipv6():
    output = os.popen("ipconfig /all").read()
    result = re.findall(r"(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})", output, re.I)
    l = []
    for i in result:
        l.append(i[0])
    return l

class BittorrentAnalyse():
    def __init__(self):
        self.up = 0
        self.down = 0
        self.remote_ipport = dict()
        self.localport = dict()
        self.type = dict()#message_type为key，handshake，continuation data, bittorrent的key分别设为-1，-2，-3
        self.type[-1] = 0
        self.type[-2] = 0
        self.type[-3] = 0
        self.ip = gethostip()
        self.ipv6 = gethostipv6()



def print_bittorrent_info(pkt: Packet, analyse: BittorrentAnalyse, l: list):
    if hasattr(pkt, 'ip'):
        if pkt.send:
            analyse.up += 1
        elif pkt.recv:
            analyse.down += 1
            if (pkt.ip.src, pkt.tcp.srcport) in analyse.remote_ipport.keys():
                analyse.remote_ipport[(pkt.ip.src, pkt.tcp.srcport)] += 1
            else:
                analyse.remote_ipport[(pkt.ip.src, pkt.tcp.srcport)] = 1
            if pkt.tcp.dstport in analyse.localport.keys():
                analyse.localport[pkt.tcp.dstport] += 1
            else:
                analyse.localport[pkt.tcp.dstport] = 1
        else:
            print('bug1')
    elif hasattr(pkt, 'ipv6'):
        if pkt.send:
            analyse.up += 1
        elif pkt.recv:
            analyse.down += 1
            if (pkt.ipv6.src, pkt.tcp.srcport) in analyse.remote_ipport.keys():
                analyse.remote_ipport[(pkt.ipv6.src, pkt.tcp.srcport)] += 1
            else:
                analyse.remote_ipport[(pkt.ipv6.src, pkt.tcp.srcport)] = 1
            if pkt.tcp.dstport in analyse.localport.keys():
                analyse.localport[pkt.tcp.dstport] += 1
            else:
                analyse.localport[pkt.tcp.dstport] = 1
        else:
            print('bug1')
    else:
        print('bug2')
    info = ''
    for layer in pkt.layers:
        if layer.layer_name == 'bittorrent':
            if hasattr(layer, 'msg_type'):
                print('message_type:%d' % int(layer.msg_type))
                info += str(layer.msg).split(', ', 1)[1] + ' '
                if int(layer.msg_type) == 7:
                    if hasattr(layer, 'piece_data'):
                        # print(l)
                        # if AC(strlist_tohexlist(l), str(layer.piece_data).replace(':', '')):

                        print('是否含有敏感词：' + str(AC(strlist_tohexlist(l), str(layer.piece_data).replace(':', ''))))
                    else:
                        print('Malformed Piece Packet')
                if int(layer.msg_type) in analyse.type.keys():
                    analyse.type[int(layer.msg_type)] += 1
                else:
                    analyse.type[int(layer.msg_type)] = 1
            else:
                if hasattr(layer, 'continuous_data'):
                    info += 'Continuation data '
                    analyse.type[-2] += 1
                    print('continue data:' + str(layer.continuous_data).replace(':', ''))
                else:
                    try:
                        info += 'Handshake '
                        info_hash = str(layer.info_hash).replace(':', '')
                        peer_id = str(layer.peer_id).replace(':', '')
                        analyse.type[-1] += 1
                        print('info hash:%s\npeer id:%s' % (info_hash, peer_id))
                    except AttributeError as e:
                        print(pkt)
                        info += 'Bittorrent '
                        analyse.type[-3] += 1
    print(info)
    print()
    return info




# if __name__ == '__main__':
#     cap = pyshark.LiveCapture(interface='WLAN', display_filter = 'bittorrent')
#     cap.apply_on_packets(print_bittorrent_info, timeout=1000)