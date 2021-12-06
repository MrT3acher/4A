# Android Application Auto Analysis (4A)

4A is a Interactive Application Security Testing (IAST) for Android. It's based on [Objection](https://github.com/sensepost/objection/) and [Frida](https://frida.re/).

## What is it?

There are two main types of software security testing:

1. Static Application Security Testing (SAST)
2. Dynamic Application Security Testing (DAST)

A lot of people believe that no one is the best! so we should merge them to get the best outcome. there are different approaches to merge SAST and DAST. One of these approaches is IAST. Android Application Auto Analysis (4A) is a tool for doing Interactive Application Security Testing. We used the power of [Frida](https://frida.re/) for Software Instrumentation and [Objection](https://github.com/sensepost/objection/) for UI/UX.

## How To Use

### Prepare Android

You have two options:

1. Use Virtual Android: **recommended for more security**

2. Use Physical Device: **recommended for better performance**

I suppose you know how to connect a virtual or physical android to your computer. When connected we run this command:

```
adb devices
```

Your android, can be discovered by 4A from now on.

### Prepare Frida

First of all, we need to prepare Frida for android. There are two options:

1. Frida Server: [Docs](https://frida.re/docs/android/), root needed
2. Frida Gadget: [Docs](https://frida.re/docs/gadget/), **recommended**

I describe second option here. thanks to Objection, Frida-Gadget injection is a peace of cake. (more info [here](https://github.com/sensepost/objection/wiki/Patching-Android-Applications))

```
objection patchapk --source app.apk
```

`app.apk` is the app that we want to analyze. after running this command, a new file get generated in the current directory, named `app.objection.apk`.

now you should install it on your device:

```
adb install app.objection.apk
```

### Run 4A

Then, run the app from android and run this command in your computer:

```
objection explore -P ./objection-plugins
```

4A is a plugin of Objection. It's easy to use :sunglasses:.

### Config Files

There are some [config files](./objection-plugins/android-sandbox/config). Just take a loot at them, too!

## Why I developed it?

This is my bachelor's project! I needed to pass the project course! :grin: the final report (in Persian/Farsi) of the project can be downloaded [here](https://github.com/MrT3acher/4A/releases/download/v1.0/report-fa.pdf).

But why I chose this topic? because I :heart: it.

There is another reason. :blush: It was so hard for me to analyze android application with current tools. I needed something new. so I built it.

## Merge Request

There are a lot of things TODO!

* **Make TypeScript code beautiful:** It's a lot of code, that can be minimized and structured. there are some repetitive structures like Hook and Switch.
* **Make Python code beautiful:** It's just one huge python file. we can divide it based on command groups.
* **Screen recording feature:** Screen record with all events and hooks that is stored on the database. This help the analyzer to playback all the events that 4A has captured.
* **Auto Interaction:** Make random or intelligence input for application.
* **Hook All:** One command for all hooks.
* any other idea...