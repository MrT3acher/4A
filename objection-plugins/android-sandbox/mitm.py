from datetime import datetime
import os
from os import path
import sys
from configparser import ConfigParser
import atexit

from unqlite import UnQLite

realpath = path.abspath(__file__)
realdir = path.dirname(realpath)

@atexit.register
def safely_close_db():
    global my_addon
    try:
        my_addon.db.close()
    except:
        pass

class MitmProxyAddon(object):
    def __init__(self) -> None:
        self.plugin_dir = path.dirname(path.abspath(__file__))

        self.data = {
            'url' : '',
            'req_method' : '',
            'req_headers': '',
            'req_body': '',
            'resp_code': '',
            'resp_headers': '',
            'resp_body': ''
        }

        # init database
        db = self._db()
        col = db.collection('proxy')
        col.create()
        db.close()

    def request(self, flow):
        self.data["url"] = flow.request.pretty_url
        self.data["req_method"] = flow.request.method
        self.data['req_headers'] = dict(flow.request.headers)
        self.data['req_body'] = flow.request.content

    def response(self, flow):
        self.data['resp_code'] = flow.response.status_code
        self.data['resp_headers'] = dict(flow.response.headers)
        self.data['resp_body'] = flow.response.content
        self.data['time'] = str(datetime.now())

        db = self._db()
        col = db.collection('proxy')
        col.store(self.data)

    def _db(self):
        conf = self._mitm_config = ConfigParser()
        confpath = path.join(self.plugin_dir, 'config/mitm.ini')
        conf.read_file(open(confpath, 'r'))
        self.db = UnQLite(conf['Proxy']['db_relative_path'])
        return self.db

my_addon = MitmProxyAddon()
addons = [
    my_addon
]