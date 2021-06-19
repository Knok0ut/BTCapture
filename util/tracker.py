import pyshark
from pyshark.packet.packet import Packet
from bencode import *
import gzip

class TrackerAnalyse():
    def __init__(self):
        self.ip_dst = set()
        self.tracker_ipport = dict()
        self.response_ipport = dict()
        self.local_port = dict()
        self.type = dict()
        self.type['Get'] = 0
        self.type['Response'] = 0
        self.peers = set()

def bytes2ipport(bytes):
    port = int.from_bytes(bytes[4:6], byteorder='big')
    ip = ''
    for i in range(4):
        ip += str(int.from_bytes(bytes[i:i + 1], byteorder='big')) + "."
    ip = ip[:-1]
    return ip + ':' + str(port)


def print_tracker_info(pkt: Packet, analyse: TrackerAnalyse):
    ip_dst = analyse.ip_dst
    tracker_ipport = analyse.tracker_ipport
    if hasattr(pkt.http, 'response'):
        if int(pkt.http.response_code) == 200:
            print('Tracker:Http Response')
            if hasattr(pkt, 'ipv6') and pkt.ipv6.src in ip_dst:
                # ip_dst.remove(pkt.ipv6.src)
                try:
                    if hasattr(pkt.http, 'data'):
                        if hasattr(pkt.http, 'content-encoding') and str(
                                getattr(pkt.http, 'content-encoding')) == 'gzip':
                            temp = bdecode(gzip.decompress(bytes.fromhex(pkt.http.data)))
                        else:
                            temp = bdecode(bytes.fromhex(pkt.http.data))
                    elif hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
                        temp = bdecode(bytes.fromhex(pkt.data.data))
                    elif hasattr(pkt, 'data-text-lines'):
                        length = int(pkt.http.content_length)
                        temp = bdecode((bytes.fromhex(pkt.tcp.payload.raw_value))[-length:])
                except BTFailure as e:
                    if hasattr(pkt.http, 'content-type') and str(getattr(pkt.http, 'content-type')) == 'application/octet-stream':
                        temp = bdecode((bytes.fromhex(pkt.tcp.payload.raw_value))[-length:-1])
                    else:
                        print(pkt)
                        print()
                        return
                except Exception as e2:
                    return
                print(temp)
                peerlist = []
                if b'peers' in temp.keys():
                    temp1 = temp[b'peers']
                    if len(temp1) > 0:
                        for i in range(len(temp1) // 6):
                            print(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                            peerlist.append(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                if b'peers6' in temp.keys():
                    temp1 = temp[b'peers6']
                    if len(temp1) > 0:
                        for i in range(len(temp1) // 6):
                            print(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                            peerlist.append(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                print()
                analyse.type['Response'] += 1
                analyse.peers = analyse.peers.union(set(peerlist))
                if (pkt.ipv6.src, pkt.tcp.srcport) in analyse.response_ipport.keys():
                    analyse.response_ipport[(pkt.ipv6.src, pkt.tcp.srcport)] += 1
                else:
                    analyse.response_ipport[(pkt.ipv6.src, pkt.tcp.srcport)] = 1
                return str(temp) + str(peerlist)

            elif hasattr(pkt, 'ip') and pkt.ip.src in ip_dst:
                # ip_dst.remove(pkt.ip.src)
                try:
                    if hasattr(pkt.http, 'data'):
                        if hasattr(pkt.http, 'content-encoding') and str(
                                getattr(pkt.http, 'content-encoding')) == 'gzip':
                            temp = bdecode(gzip.decompress(bytes.fromhex(pkt.http.data)))
                        else:
                            temp = bdecode(bytes.fromhex(pkt.http.data))
                    elif hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
                        temp = bdecode(bytes.fromhex(pkt.data.data))
                    elif hasattr(pkt, 'data-text-lines'):
                        length = int(pkt.http.content_length)
                        temp = bdecode((bytes.fromhex(pkt.tcp.payload.raw_value))[-length:])
                except BTFailure as e:
                    try:
                        temp = bdecode((bytes.fromhex(pkt.tcp.payload.raw_value))[-length:-1])
                    except:
                        print(pkt)
                        print()
                        return
                except Exception as e2:
                    return
                # else:
                #     print('bug')
                #     print(pkt.http.file_data)
                print(temp)
                peerlist = []
                if b'peers' in temp.keys():
                    temp1 = temp[b'peers']
                    if len(temp1) > 0:
                        for i in range(len(temp1) // 6):
                            print(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                            peerlist.append(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                if b'peers6' in temp.keys():
                    temp1 = temp[b'peers6']
                    if len(temp1) > 0:
                        for i in range(len(temp1) // 6):
                            print(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                            peerlist.append(bytes2ipport(temp1[(i * 6):(i * 6 + 6)]))
                print()
                analyse.type['Response'] += 1
                analyse.peers = analyse.peers.union(set(peerlist))
                if (pkt.ip.src, pkt.tcp.srcport) in analyse.response_ipport.keys():
                    analyse.response_ipport[(pkt.ip.src, pkt.tcp.srcport)] += 1
                else:
                    analyse.response_ipport[(pkt.ip.src, pkt.tcp.srcport)] = 1
                return str(temp) + str(peerlist)
    else:
        if hasattr(pkt.http, 'request_uri') and ((
                'announce' in pkt.http.request_uri or 'scrape' in pkt.http.request_uri)):
            print('Tracker:Http Get')
            if hasattr(pkt, 'ipv6'):
                ip_dst.add(pkt.ipv6.dst)
                print(pkt.ipv6.src + '->' + pkt.ipv6.dst + '\n' + pkt.http.request_uri)
                print()
                if (pkt.ipv6.dst, pkt.tcp.dstport) in tracker_ipport.keys():
                    tracker_ipport[(pkt.ipv6.dst, pkt.tcp.dstport)] = tracker_ipport[
                                                                          (pkt.ipv6.dst, pkt.tcp.dstport)] + 1
                else:
                    tracker_ipport[(pkt.ipv6.dst, pkt.tcp.dstport)] = 1
            elif hasattr(pkt, 'ip'):
                ip_dst.add(pkt.ip.dst)
                print(pkt.ip.src + '->' + pkt.ip.dst + '\n' + pkt.http.request_uri)
                print()
                if (pkt.ip.dst, pkt.tcp.dstport) in tracker_ipport.keys():
                    tracker_ipport[(pkt.ip.dst, pkt.tcp.dstport)] = tracker_ipport[(pkt.ip.dst, pkt.tcp.dstport)] + 1
                else:
                    tracker_ipport[(pkt.ip.dst, pkt.tcp.dstport)] = 1
            if pkt.tcp.srcport in analyse.local_port.keys():
                analyse.local_port[pkt.tcp.srcport] += 1
            else:
                analyse.local_port[pkt.tcp.srcport] = 1
            analyse.type['Get'] += 1
            return pkt.http.request_uri


# if __name__ == '__main__':
#     cap = pyshark.LiveCapture(interface='WLAN', display_filter='http')
#     cap.apply_on_packets(print_tracker_info, timeout=1000)
