import sched, time
import atexit
from datetime import datetime

from unqlite import UnQLite

@atexit.register
def safely_close_db():
    del Database.singleton

class Database:
    timeout = 10
    singleton = None

    def __init__(self, db_file = None):
        if db_file == None:
            Database.singleton = self
            db_file = 'data.db'
        self.db_file = db_file
        self.sched = sched.scheduler(time.time, time.sleep)

    def add_to_plugin(self, plugin, data):
        data['time'] = str(datetime.now())
        db = self.db
        col = db.collection(plugin)
        col.create() # create collection if not exist
        col.store(data) # then store it in the collection

    def get_plugin_data(self, plugin):
        db = self.db
        col = db.collection(plugin)
        return col

    def get_plugins(self):
        db = self.db
        plugins = set()
        for k in db.keys():
            plugin = '_'.join(k.split('_')[:-1])
            if plugin == '':
                continue

            plugins.add(plugin)
        return plugins

    @property
    def db(self):
        """
        db property manage private _db property and cause the database connection be closed after 10 seconds, if not used
        """
        self._open_db()
        return self._db

    def close_db(self):
        if hasattr(self, '_db'):
            self._db.close()
            del self._db

    def _open_db(self):
        if hasattr(self, '_db') and hasattr(self, '_event'):
            self.sched.cancel(self._event)
        else:
            self._db = UnQLite(self.db_file)
        self._event = self.sched.enter(self.timeout, 1, self.close_db)

    def __del__(self):
        self.close_db()