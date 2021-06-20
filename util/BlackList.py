import requests
import json
import pymongo


client = pymongo.MongoClient('mongodb://localhost:27017')
db = client["BTCapture"]
document = db["BlackList"]
black_id = "black"
record_id = "record"


class BlackList:
    def __init__(self):
        self.session = requests.session()
        self.url = "http://39.105.175.67:8000/getBlackList"
        self.black_list = None

    def refresh_from_server(self) -> bool:
        res = self.session.get(self.url)
        if res.status_code == 200:
            black_list = json.loads(res.text)['blacklist']
            if self.get_black_list() is not None:
                document.replace_one({"_id": black_id}, {"_id": black_id, record_id: black_list})
                return True
            else:
                document.insert({"_id": black_id, record_id: black_list})
        else:
            return False

    def get_black_list(self):
        res = document.find_one({"_id": black_id})[record_id]
        return res

    def remove(self, item: str):
        res: list = self.get_black_list()
        item = item.strip()
        if res:
            if item in res:
                res.remove(item)
                document.replace_one({"_id": black_id}, {"_id": black_id, record_id: res})

    def add(self, item: str):
        res: list = self.get_black_list()
        if res is not None:
            res.append(item.strip())
            res = list(set(res))
            document.replace_one({"_id": black_id}, {"_id": black_id, record_id: res})
        else:
            document.insert({"_id": black_id, record_id: [item.strip()]})

    # def save_blacklist(self, ls: list):
    #     document.save(ls)
    # if self.black_list:
    #     return self.black_list
    # res = self.session.get(self.url)
    # if res.status_code == 200:
    #     self.black_list = json.loads(res.text)['blacklist']
    #     return self.black_list
    # else:
    #     self.black_list = None
    #     return self.black_list
