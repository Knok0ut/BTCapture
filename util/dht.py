import pyshark
from pyshark.packet.packet import Packet
from bencode import *
# todo:DHT报文类型统计 端口统计 nodes/peers统计？
class DHTAnalyse():
    def __init__(self):
        self.requested_ipport = dict()
        self.response_ipport = dict()
        self.type = dict()
        self.type['response'] = 0
        self.nodes = set()
        self.peers = set()

def handle_nodes(nodes: bytes, analyse: DHTAnalyse):
    counter = 0
    while len(nodes) != 0:
        id = nodes[:20].hex()
        nodes = nodes[20:]
        ip = ''
        for i in range(4):
            ip += str(int.from_bytes(nodes[i:i + 1], byteorder='big')) + "."
        ip = ip[:-1]
        port = int.from_bytes(nodes[4:6], byteorder='big')
        nodes = nodes[6:]
        counter += 1
        print('Node %d:\nid:%s\nip:%s\nport:%d'%(counter, id, ip, port))
        analyse.nodes.add((id, ip, port))
    return counter

def handle_peers(peers: list, analyse: DHTAnalyse):
    counter = 0
    for peer in peers:
        ip = ''
        for i in range(4):
            ip += str(int.from_bytes(peer[i:i + 1], byteorder='big')) + "."
        ip = ip[:-1]
        port = int.from_bytes(peer[4:6], byteorder='big')
        counter += 1
        print('Peer %d:\nip:%s\nport:%d' % (counter, ip, port))
        analyse.peers.add((ip, port))
    return counter
    #  
    # while len(peers) != 0:
    #     ip = ''
    #     for i in range(4):
    #         ip += str(int.from_bytes(peers[i:i + 1], byteorder='big')) + "."
    #     ip = ip[:-1]
    #     port = int.from_bytes(peers[4:6], byteorder='big')
    #     peers = peers[6:]
    #     counter += 1
    #     print('Peer %d:\nip:%s\nport:%d' % (counter, ip, port))
    # return counter

def handle_dht_message(dht_message: dict, analyse: DHTAnalyse, src_ipport, dst_ipport):
    m_type = dht_message[b'y']
    if m_type == b'q':
        #请求
        q_type = dht_message[b'q']
        if q_type.decode() in analyse.type.keys():
            analyse.type[q_type.decode()] += 1
        else:
            analyse.type[q_type.decode()] = 1
        if dst_ipport in analyse.requested_ipport.keys():
            analyse.requested_ipport[dst_ipport] += 1
        else:
            analyse.requested_ipport[dst_ipport] = 1
        if q_type == b'find_node':
            a = dht_message[b'a']
            print('Find_node:\nid:' + a[b'id'].hex() + '\ntarget:' + a[b'target'].hex() + '\n')
            return 'Request: find_node'
        elif q_type == b'get_peers':
            a = dht_message[b'a']
            print('Get_peers:\nid:' + a[b'id'].hex() + '\ninfo_hash:' + a[b'info_hash'].hex() + '\n')
            return 'Request: get_peers'
        else:
            print(q_type.decode().capitalize() + '\n')
            return 'Request: %s' % q_type.decode()
            #ping或announce_peer，暂不处理
    else:
        r = dht_message[b'r']
        analyse.type['response'] += 1
        if src_ipport in analyse.response_ipport.keys():
            analyse.response_ipport[src_ipport] += 1
        else:
            analyse.response_ipport[src_ipport] = 1
        id = r[b'id']
        print('Response:\nId:%s'%id.hex())
        nodes_num = 0
        peers_num =  0
        if b'nodes' in r.keys():
            nodes_num = handle_nodes(r[b'nodes'], analyse)
        if b'values' in r.keys():
            peers_num = handle_peers(r[b'values'], analyse)
        # print(dht_message)
        print('Totol:%d node(s), %d peer(s)\n'%(nodes_num, peers_num))
        return 'Response: %d node(s), %d peer(s)' % (nodes_num, peers_num)

def print_dht_info(pkt: Packet, analyse: DHTAnalyse):
    if hasattr(pkt, 'icmp'):
        print(pkt.icmp)
        return 'ICMP'
    else:
        print('DHT')
        if hasattr(pkt, 'ip'):
            print(pkt.ip.src + ':' + pkt.udp.srcport + '->' + pkt.ip.dst + ':' + pkt.udp.dstport)
            src_ipport = (pkt.ip.src, pkt.udp.srcport)
            dst_ipport = (pkt.ip.dst, pkt.udp.dstport)
        elif hasattr(pkt, 'ipv6'):
            print(pkt.ipv6.src + ':' + pkt.udp.srcport + '->' + pkt.ipv6.dst + ':' + pkt.udp.dstport)
            src_ipport = (pkt.ipv6.src, pkt.udp.srcport)
            dst_ipport = (pkt.ipv6.dst, pkt.udp.dstport)
        try:
            return handle_dht_message(bdecode(bytes.fromhex(pkt.udp.payload.raw_value)), analyse, src_ipport, dst_ipport)
        except KeyError as e1:
            print(str(e1) + '\n')
        except BTFailure as e2:
            print('Malformed DHT Packet\n')

# if __name__ == '__main__':
#     cap = pyshark.LiveCapture(interface='WLAN', display_filter = 'udp.port == 51934', decode_as={'udp.port == 51934' : 'bt-dht'})
#     cap.apply_on_packets(print_dht_info, timeout=1000)