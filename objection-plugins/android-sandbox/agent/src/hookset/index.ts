import { base64 } from "./base64";
import { cihper } from "./cipher";
import { dex } from "./dex";
import { file } from "./file";
import { hash } from "./hash";
import { json } from "./json";
import { log } from "./log";
import { proxy } from "./proxy";
import { prefs } from "./preferences";
import { socket } from "./socket";
import { strings } from "./strings";
import { url } from "./url";
import { library } from "./library";
import { webview } from "./webview";
import { sqlite } from "./sqlite";
import { clipboard } from "./clipboard";
import { serialize } from "./serialize";

export const hooks = {
  hookBase64: base64.hook,
  hookCipher: cihper.hook,
  hookClipboard: clipboard.up,
  hookDex: dex.hook,
  hookFile: file.hook,
  hookHash: hash.hook,
  hookJson: json.hook,
  hookLibrary: library.hook,
  hookLog: log.hook,
  hookProxy: proxy.hook,
  hookSerialize: serialize.up,
  hookPrefs: prefs.hook,
  hookSocket: socket.hook,
  hookSqlite: sqlite.up,
  hookStrings: strings.hook,
  hookUrl: url.hook,
  hookWebview: webview.up
};

export const unhooks = {
  unhookBase64: base64.unhook,
  unhookCipher: cihper.unhook,
  unhookClipboard: clipboard.down,
  unhookDex: dex.unhook,
  unhookFile: file.unhook,
  unhookHash: hash.unhook,
  unhookJson: json.unhook,
  unhookLibrary: library.unhook,
  unhookLog: log.unhook,
  unhookProxy: proxy.unhook,
  unhookSerialize: serialize.down,
  unhookPrefs: prefs.unhook,
  unhookSocket: socket.unhook,
  unhookSqlite: sqlite.down,
  unhookStrings: strings.unhook,
  unhookUrl: url.unhook,
  unhookWebview: webview.down
}
