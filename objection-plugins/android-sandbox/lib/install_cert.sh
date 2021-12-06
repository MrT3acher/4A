#!/bin/bash
# this script will install mitmproxy certificate on the android device via `adb`
ca=$1

hash=$(openssl x509 -inform PEM -subject_hash_old -in $ca | head -1)
cert_name=$hash.0
cert_dir="/system/etc/security/cacerts"
cert_path="$cert_dir/$cert_name"
cert_temp="/storage/sdcard0/$cert_name"

su_cmd(){
    echo $1 | adb shell su
}

if adb root | grep 'adbd cannot run as root in production builds'; then # physical device
    echo -n 'It seems you are using a physical device. no matter ;)'

    adb push $ca $cert_temp
    su_cmd "mount -t tmpfs tmpfs $cert_dir"
    su_cmd "mv $cert_temp $cert_path"
    su_cmd "chown root:root $cert_dir/*"
    su_cmd "chmod 644 $cert_dir/*"
    su_cmd "chcon u:object_r:system_file:s0 $cert_dir/*"
    
else # virtual device
    adb remount
    adb push $ca $cert_path
    adb reboot
fi