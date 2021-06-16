import pyshark
from pyshark.packet.packet import Packet

def print_bittorrent_info(pkt: Packet):
    # print(pkt.bittorrent)
    info = ''
    for layer in pkt.layers:
        if layer.layer_name == 'bittorrent':
            if hasattr(layer, 'msg_type'):
                info += str(layer.msg).split(', ', 1)[1] + ' '
            else:
                if hasattr(layer, 'continuous_data'):
                    info += 'Continuation data'
                    print('continue data:' + str(layer.continuous_data).replace(':', ''))
                else:
                    try:
                        info += 'Handshake'
                        info_hash = str(layer.info_hash).replace(':', '')
                        peer_id = str(layer.peer_id).replace(':', '')
                        print('info hash:%s\npeer id:%s' % (info_hash, peer_id))
                    except AttributeError as e:
                        # print('bug: ' + str(e))
                        return
    print(info)
    print()
    return info




if __name__ == '__main__':
    cap = pyshark.LiveCapture(interface='WLAN', display_filter = 'bittorrent')
    cap.apply_on_packets(print_bittorrent_info, timeout=1000)