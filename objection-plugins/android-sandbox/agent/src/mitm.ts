const $System = Java.use("java.lang.System")

export function mitmSetProxy(host, port) {
    Java.perform(function() {
        var properties = $System.getProperties();
        properties.setProperty("http.proxyHost", host.toString());
        properties.setProperty("http.proxyPort", port.toString());
        properties.setProperty("https.proxyHost", host.toString());
        properties.setProperty("https.proxyPort", port.toString());
    })
}

export function mitmUnsetProxy() {
    Java.perform(function() {
        var properties = $System.getProperties();
        properties.setProperty("http.proxyHost", "");
        properties.setProperty("http.proxyPort", "");
        properties.setProperty("https.proxyHost", "");
        properties.setProperty("https.proxyPort", "");
    })
}