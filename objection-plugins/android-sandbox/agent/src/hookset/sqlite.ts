import { Switch } from "../lib/switch";
import { stackTrace } from "./lib/thread";

const $SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

function hook()
{
    /*
        Idea from https://codeshare.frida.re/@ninjadiary/sqlite-database/
    * */

    // execSQL(String sql)
    $SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(var0) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.execSQL('java.lang.String')", "query": var0, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.execSQL(var0);
        return result;
    };

    // execSqL(String, sql, Obj[] bindArgs)
    $SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(var0, var1) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.execSQL('java.lang.String', '[Ljava.lang.Object;')", "query": var0, 'binds': var1, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.execSQL(var0, var1);
        return result;
    };

    // query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
    $SQLiteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.query('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String')",
            "table": var1, 'selection': var3, 'selectionArgs': var4, 'distinct': var0, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8);
        return result;
    };

    // query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
    $SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.query('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String')",
            "table": var0, 'selection': var2, 'selectionArgs': var3, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.query(var0, var1, var2, var3, var4, var5, var6, var7);
        return result;
    };

    // query(boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
    $SQLiteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.query('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal')",
            "table": var1, 'selection': var3, 'selectionArgs': var4, 'distinct': var0, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.query(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
        return result;
    };

    // query(String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy)
    $SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.query('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String')",
            "table": var0, 'selection': var2, 'selectionArgs': var3, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.query(var0, var1, var2, var3, var4, var5, var6);
        return result;
    };

    // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit, CancellationSignal cancellationSignal)
    $SQLiteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.queryWithFactory('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String')",
            "table": var2, 'selection': var4, 'selectionArgs': var5, 'distinct': var1, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9);
        return result;
    };   		

    // queryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, boolean distinct, String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
    $SQLiteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.queryWithFactory('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal')",
            "table": var2, 'selection': var4, 'selectionArgs': var5, 'distinct': var1, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.queryWithFactory(var0, var1, var2, var3, var4, var5, var6, var7, var8, var9, var10);
        return result;
    }; 

    // rawQuery(String sql, String[] selectionArgs) 
    $SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(var0, var1) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.rawQuery('java.lang.String', '[Ljava.lang.String;')",
            "query": var0, 'contentValues': var1, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.rawQuery(var0, var1);
        return result;
    };

    // rawQuery(String sql, String[] selectionArgs, CancellationSignal cancellationSignal)
    $SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal').implementation = function(var0, var1, var2) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.rawQuery('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal')",
            "query": var0, 'contentValues': var1, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.rawQuery(var0, var1, var2);
        return result;
    };

    // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable, CancellationSignal cancellationSignal)
    $SQLiteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = function(var0, var1, var2, var3, var4) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.rawQueryWithFactory('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal')",
            "query": var1, 'contentValues': var2, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.rawQueryWithFactory(var0, var1, var2, var3, var4);
        return result;
    };

    // rawQueryWithFactory(SQLiteDatabase.CursorFactory cursorFactory, String sql, String[] selectionArgs, String editTable)
    $SQLiteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(var0, var1, var2, var3) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.rawQueryWithFactory('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String')",
            "query": var1, 'contentValues': var2, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.rawQueryWithFactory(var0, var1, var2, var3);
        return result;
    };

    // insert(String table, String nullColumnHack, ContentValues values)
    $SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(var0, var1, var2) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.insert('java.lang.String', 'java.lang.String', 'android.content.ContentValues')",
            "table": var0, 'contentValues': var2, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.insert(var0, var1, var2);
        return result;
    };

    // insertOrThrow(String table, String nullColumnHack, ContentValues values)
    $SQLiteDatabase.insertOrThrow.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(var0, var1, var2) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.insertOrThrow('java.lang.String', 'java.lang.String', 'android.content.ContentValues')",
            "table": var0, 'contentValues': var2, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.insertOrThrow(var0, var1, var2);
        return result;
    };

    // insertWithOnConflict(String table, String nullColumnHack, ContentValues initialValues, int conflictAlgorithm)
    $SQLiteDatabase.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int').implementation = function(var0, var1, var2, var3) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.insertWithOnConflict('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int')",
            "table": var0, 'contentValues': var2, 'conflictAlgorithm': var3, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.insertWithOnConflict(var0, var1, var2, var3);
        return result;
    };

    // update(String table, ContentValues values, String whereClause, String[] whereArgs)
    $SQLiteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = function(var0, var1, var2, var3) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.update('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;')",
            "table": var0, 'contentValues': var1.toString(), 'where': var2, 'whereArgs': var3.toString(), 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.update(var0, var1, var2, var3);
        return result;
    };

    // updateWithOnConflict(String table, ContentValues values, String whereClause, String[] whereArgs, int conflictAlgorithm) 
    $SQLiteDatabase.updateWithOnConflict.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int').implementation = function(var0, var1, var2, var3, var4) {
        var stack = stackTrace()
        var obj = {"plugin": "sqlite", "method": "SQLiteDatabase.updateWithOnConflict('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int')",
            "table": var0, 'contentValues': var1.toString(), 'where': var2, 'whereArgs': var3.toString(), 'conflictAlgorithm': var4, 'stack': stack.join('\n')}
        send(JSON.stringify(obj))
        var result = this.updateWithOnConflict(var0, var1, var2, var3, var4);
        return result;
    };
}

function unhook()
{
    $SQLiteDatabase.execSQL.overload('java.lang.String').implementation = null
    $SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = null
    $SQLiteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = null
    $SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = null
    $SQLiteDatabase.query.overload('boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = null
    $SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = null
    $SQLiteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = null   		
    $SQLiteDatabase.queryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'boolean', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'android.os.CancellationSignal').implementation = null 
    $SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = null
    $SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;', 'android.os.CancellationSignal').implementation = null
    $SQLiteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').implementation = null
    $SQLiteDatabase.rawQueryWithFactory.overload('android.database.sqlite.SQLiteDatabase$CursorFactory', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = null
    $SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = null
    $SQLiteDatabase.insertOrThrow.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = null
    $SQLiteDatabase.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int').implementation = null
    $SQLiteDatabase.update.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;').implementation = null
    $SQLiteDatabase.updateWithOnConflict.overload('java.lang.String', 'android.content.ContentValues', 'java.lang.String', '[Ljava.lang.String;', 'int').implementation = null
}

export const sqlite = new Switch(hook, unhook)