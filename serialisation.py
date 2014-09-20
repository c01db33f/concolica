

import cPickle as pickle
import zlib

def save(file, item):
    data = pickle.dumps(item, pickle.HIGHEST_PROTOCOL)
    data = zlib.compress(data)
    with open(file, 'wb') as tmp:
        tmp.write(data)

def load(file):
    with open(file, 'rb') as tmp:
        data = tmp.read()
        data = zlib.decompress(data)
        item = pickle.loads(data)
        return item
