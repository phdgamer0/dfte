# Privacy policy

Last updated: 30 October 2026

This policy covers the DFTE apps: the Android app (package `dev.dfte.app`) and the two Linux programs, `dfte` (command line) and `dfte-gtk` (desktop). Windows and iOS versions don't exist yet. When they do, this page will be updated before they are released.

DFTE is made by Yazdan Samari ("I" below). The source code is at https://github.com/phdgamer0/dfte.

## The short version

DFTE moves files from one of your devices to another device near you, over your local Wi-Fi network or a direct Wi-Fi link between the two devices. It never connects to the internet. There is no DFTE server, no account, no analytics, no ads and no crash reporting. I don't receive any information about you or your files.

## What I collect

Nothing. The apps have no code that sends data to me or to anyone else besides the device you are transferring with. No server exists that could receive it.

If you open an issue or a security advisory on GitHub, what you write there is handled by GitHub under its own privacy policy. Issues are public, so don't paste anything private into one.

## What the app keeps on your device

DFTE stores a few things locally so it can work. None of it leaves your device, except where a section below says so.

Device identity key. On first launch DFTE creates a key pair that identifies your device to others. On Android the secret half is encrypted with a key held in the Android Keystore and saved in app storage that is excluded from backups. On Linux it is saved in `~/.local/share/dfte/identity.key` (or under `$XDG_DATA_HOME/dfte`), readable only by your user account. The Linux apps refuse to use the file if other users can read it. The public half of the key is what other devices see (described below).

Trusted devices. When you check a device's code and choose to remember it, DFTE saves that device's fingerprint and name so you don't have to check again next time. On Android this is in the app's private settings. On Linux it is `trusted.json` in the same folder as the key, also readable only by you.

Files you receive. While a transfer is running, incoming data is written to the app's own folder. If a transfer is interrupted, the partial file and a small resume record (the list of files, their sizes and hashes, and how much has arrived) stay there so the transfer can continue later. When a transfer finishes and passes its integrity check, the files are moved to Downloads/DFTE on Android, or to your Downloads folder on Linux.

Files you send. To avoid reading a large file twice when you send it again or resume, DFTE keeps a cache of each sent file's full path, size, modification times and content hashes (not its contents). On Linux both apps use `~/.cache/dfte/hashes` (or `$XDG_CACHE_HOME/dfte/hashes`), and only files of 4 MiB or more are listed. On Android it is in the app's own storage. On Android, files you pick from other apps are read where they are and are not copied.

Logs. DFTE writes diagnostic messages so problems can be tracked down. On Linux they go to the terminal only and are not saved to a file. On Android they go to the system log. Other apps can't read it, though a computer connected with USB debugging can. Logs can include device names, short fingerprints, file names, sizes and error messages. They never include encryption keys or the contents of your files.

To remove everything: on Android, uninstall the app (files already moved to Downloads/DFTE stay where they are). On Linux, delete the folders `~/.local/share/dfte` and `~/.cache/dfte`. If you delete the identity key, DFTE makes a new one, and devices that trusted you will have to check your code again.

## What nearby devices can see

To be found, DFTE announces itself on the local network. On Android this happens while the Send or Receive screen is open. The Linux desktop app does it while it is open, and the command-line app while a `send` or `receive` command is running. Each announcement contains:

- your device name (on Android, the name set in system settings, or the phone model if none is set; on Linux, the computer's hostname, or `DFTE_DEVICE_NAME` if you set it)
- your device's public identity key, from which the fingerprint shown in the app is computed
- the port DFTE is listening on, and the time on your device's clock

Announcements are signed but not encrypted. They are sent to a local multicast address that routers don't forward beyond your network, and to devices on your network that have answered. Anyone on the same Wi-Fi network or Wi-Fi Direct group who runs DFTE, or who captures network traffic, can see that your device is running DFTE and what it is called. If that matters to you, change your device name or only open DFTE on networks you trust.

When you use Wi-Fi Direct on Android, nearby devices can also see your phone's Wi-Fi Direct name. That name is set by Android, not by DFTE.

Everything after the announcement is encrypted, including file names and sizes. The device you send to gets the files, their names, sizes and modification times. Someone listening on the radio can still tell that two devices are exchanging data and roughly how much, but not what it is.

## Android permissions

Android asks you for some of these when you first use the feature that needs them. The others are granted at install time.

Internet (`INTERNET`). Android requires this for any network connection, including ones that stay inside your home Wi-Fi. DFTE uses it to talk to the other device over your local network or Wi-Fi Direct link. It has no code that contacts servers on the internet, and its announcements are only sent to private and link-local addresses.

Network and Wi-Fi state (`ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`). To check whether Wi-Fi is on, find this device's address on the local network, and start Wi-Fi Direct.

Wi-Fi multicast (`CHANGE_WIFI_MULTICAST_STATE`). Android drops multicast packets by default to save battery. DFTE turns multicast reception on while it is looking for devices, so it can hear their announcements.

Precise location (`ACCESS_FINE_LOCATION`), Android 12 and older only. Android requires this permission before an app can use Wi-Fi Direct, because Wi-Fi scan results could in theory reveal where you are. DFTE never reads your location. On these versions Android may also ask you to turn on location services before Wi-Fi Direct can find devices.

Nearby Wi-Fi devices (`NEARBY_WIFI_DEVICES`), Android 13 and newer. This replaces the location permission for Wi-Fi Direct. DFTE declares it with Android's "never for location" flag, which tells the system the app doesn't use it to work out your location.

Foreground service (`FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`). Lets a transfer keep running when you switch to another app or the screen turns off. Android shows a notification while this is happening.

Notifications (`POST_NOTIFICATIONS`). To show transfer progress and when a transfer finishes. You can refuse; transfers still work.

Wake lock (`WAKE_LOCK`). Keeps the processor awake during a transfer so it doesn't stall with the screen off. DFTE releases it when the transfer ends.

Storage (`WRITE_EXTERNAL_STORAGE`), Android 8 and 9 only. Needed on those versions to put received files in Downloads/DFTE. Newer versions of Android don't need it.

DFTE also shows up in the Android share menu. It only sees files you choose to share with it.

DFTE doesn't ask for access to your camera, microphone, contacts, accounts, photos library or call logs. App backup is turned off, so DFTE's data is not copied to your Google account.

## Children

DFTE is not aimed at children. It doesn't collect anything from anyone, children included.

## Changes to this policy

If the apps start handling data differently, this file will be updated before that version is released, and the date at the top will change. The full history of this file is in the repository's git log.

## Contact

Questions about this policy: open an issue at https://github.com/phdgamer0/dfte/issues. To report a security problem privately, see [SECURITY.md](../../SECURITY.md).
