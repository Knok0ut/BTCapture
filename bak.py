import pyshark


def haha(pkt):
    print("hello")
    print(pkt)


capture = pyshark.LiveCapture(interface='WLAN', display_filter="dns")

capture.debug = True

capture.apply_on_packets(haha, timeout=100)
