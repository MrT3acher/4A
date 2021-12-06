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
    su_cmd "umount $cert_dir"
else # virtual device
    adb remount
    adb shell "rm $cert_path"
    adb reboot
fi