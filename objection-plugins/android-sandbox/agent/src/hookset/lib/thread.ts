const $thread = Java.use('java.lang.Thread');
const $threadnew = $thread.$new();

export function stackTrace()
{
    return $threadnew.currentThread().getStackTrace();
}