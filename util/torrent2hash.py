import magneturi
import base64

def torrent2hash(filepath: str):
    mangetlink = magneturi.from_torrent_file(filepath)
    b32Hash = mangetlink.split('btih:')[1].split('&')[0]
    b16Hash = base64.b16encode(base64.b32decode(b32Hash))
    b16Hash = b16Hash.lower()
    b16Hash = str(b16Hash,"utf-8")
    return b16Hash
if __name__ == '__main__':
    print(torrent2hash('C:\\Users\\Anakin Skywalker\\Desktop\\信息内容安全\\ICSLab\\博人传200.torrent'))
