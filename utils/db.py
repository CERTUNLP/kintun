from pymongo import MongoClient

def setup_db(dbconf):
    client = MongoClient(dbconf['host'], dbconf['port'], username=dbconf['user'], password=dbconf['password'])
    db = client[dbconf['db']]
    print(dbconf['user'], dbconf['password'])
    return db