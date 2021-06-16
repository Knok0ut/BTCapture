import pymongo

client = pymongo.MongoClient('mongodb://localhost:27017')
db = client["test"]
c_set = db["PacketDictTest"]
