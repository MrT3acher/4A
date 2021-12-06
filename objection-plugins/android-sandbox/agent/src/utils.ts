const $ActivityThread = Java.use('android.app.ActivityThread')
const $Context = Java.use('android.content.Context');
const $Intent = Java.use("android.content.Intent");

export function utilsAppInfo()
{
    var res
    Java.perform(() => {
        var $currentApplication = $ActivityThread.currentApplication();
        var $context = $currentApplication.getApplicationContext();

        res = {
            appName: $context.getPackageName(),
            filesDirectory: $context.getFilesDir().getAbsolutePath().toString(),
            cacheDirectory: $context.getCacheDir().getAbsolutePath().toString(),
            externalCacheDirectory: $context.getExternalCacheDir().getAbsolutePath().toString(),
            codeCacheDirectory: $context.getCodeCacheDir().getAbsolutePath().toString(),
            obbDir: $context.getObbDir().getAbsolutePath().toString(),
            packageCodePath: $context.getPackageCodePath().toString()
        };
    })
    return res
}

// export function utilsProxyChange()
// {
//     Java.perform(() => {
//         var intent = $Intent.$new();
//         intent.setAction("android.intent.action.PROXY_CHANGE");
//     })
// }