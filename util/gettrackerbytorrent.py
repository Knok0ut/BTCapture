import bencode
import socket
import re

def get_ip_list(domain): # 获取域名解析出的IP列表
  ip_list = []
  try:
    addrs = socket.getaddrinfo(domain, None)
    for item in addrs:
      if item[4][0] not in ip_list:
        ip_list.append(item[4][0])
  except Exception as e:
    # print(str(e))
    pass
  return ip_list

def get_tracker(filepath):
    with open(filepath, "rb") as f:
        content = f.read()
    d = bencode.bdecode(content)
    if b'announce-list' in d.keys():
        flbyte = [i[0] for i in d[b'announce-list']]
        flbyte.append(d[b'announce'])
    else:
        flbyte = [d[b'announce']]
    flip = []
    for i in range(len(flbyte)):
        temp = re.split(':|/', flbyte[i].decode().split('//')[1])[0]
        flip += get_ip_list(temp)
    return flip

# print(get_tracker('博人传200.torrent'))
# print(get_tracker('log2.torrent'))