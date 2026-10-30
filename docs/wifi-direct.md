# Wi-Fi Direct

DFTE can move files between a Linux laptop and an Android phone over Wi-Fi Direct, with no router and no shared network. This page describes how that works today, what got in the way during testing, and how to get unstuck.

Everything here was tested with one pair of devices: an Intel AX201 laptop (iwlwifi) on Arch Linux with NetworkManager 1.58.1 and wpa_supplicant 2.12, and a Samsung Galaxy A30 on Android 11. Other hardware may behave differently. Wi-Fi Direct driver quality varies a lot, especially with cheap USB adapters.

## What works

| Pair | Wi-Fi Direct? |
|---|---|
| Linux laptop and Android phone | Yes. The laptop starts the connection. |
| Android and Android | No. The Android app can't start a connection, only accept one. Use a shared network. |
| Linux and Linux | Not expected to work and not tested. NetworkManager never answers incoming requests, so two NetworkManager machines can't pair. Use a shared network. |
| Anything and iPhone | No. iOS has no Wi-Fi Direct API. The planned route is a hotspot the iPhone joins after scanning a QR code; it isn't built. |

## How it works

### Linux

The Linux side goes through NetworkManager's D-Bus API (`discovery/src/nm.rs`), not through `wpa_supplicant` directly. On a normal desktop NetworkManager owns wpa_supplicant, and wpa_supplicant's D-Bus policy only admits root. NetworkManager authorizes ordinary users through polkit, so DFTE needs no root and no system configuration changes.

When you run `dfte send --wifi-direct NAME` (or `receive`, or `peers`), dfte:

1. asks NetworkManager to search for Wi-Fi Direct devices and waits up to 20 seconds for one whose name or P2P address matches NAME;
2. asks NetworkManager to connect to it and waits up to 60 seconds for the group to come up. The phone may ask its user to accept;
3. runs the command as usual. LAN beacons now also go to the other end of the group, and the two sides learn each other's port and fingerprint from them;
4. leaves the group when the command ends.

The group only provides IP addresses. Authentication is the same as on any other network: the security code, a trusted fingerprint, or `--expect`.

If the Wi-Fi card supports a station interface and a P2P interface at the same time, the laptop stays on its normal Wi-Fi network while the group runs on a separate `p2p-*` interface. The AX201 does (up to two channels). Check yours with `iw list` under "valid interface combinations".

In the desktop app, the same thing is on the Receive page: type the phone's Wi-Fi Direct name and press Connect. Once connected, the phone appears on the Send page.

### Android

The phone doesn't host a group and doesn't start connections. While DFTE's Send or Receive screen is open, it keeps the phone discoverable. When the laptop connects, Android shows its own prompt, Wi-Fi Direct negotiation decides which side becomes group owner, and the owner hands out addresses.

The app needs one extra permission for Wi-Fi Direct: "Nearby Wi-Fi devices" on Android 13 and newer, Location on older versions. DFTE never reads your location. Android just files Wi-Fi Direct under it.

## Limitations found in testing

### NetworkManager only starts negotiations

It never answers an incoming request and can't join a group someone else already hosts. Android in turn refuses to negotiate while it already owns a group. That's why the laptop always initiates and the phone only stays discoverable, and why the phone can't simply host a group for the laptop to join through NetworkManager's P2P support.

### Whoever owns the group serves DHCP

- If the phone becomes owner, it hands out an address in 192.168.49.0/24 and the laptop's gateway on that interface is the phone.
- If the laptop becomes owner, NetworkManager's "shared" IPv4 mode needs `dnsmasq` to run the DHCP server. Without it the phone gets no IPv4 address and drops the group a few seconds later. Install the `dnsmasq` package. Ubuntu and Debian usually pull it in with NetworkManager; on the Arch test laptop it had to be installed by hand.

You can't choose which side becomes owner; negotiation decides.

### Groups are 20 MHz wide and slow

NetworkManager's groups came up at 72 Mbit/s PHY: 2.4 GHz channel 6 when the phone was owner, 5 GHz channel 149 when the laptop was. engine-bench managed 3.3 MiB/s over that, and the apps 2.3–3.1 MiB/s. That's the radio's limit. The same phone did 25–32 MiB/s through its own 80 MHz hotspot.

An experiment had the phone host a 5 GHz, 80 MHz group itself, with the laptop joining it as an ordinary Wi-Fi client (`nmcli device wifi connect`). That reached 9.7–11.6 MiB/s at 433 Mbit/s PHY. The rest of the gap to the hotspot numbers is most likely the phone splitting its radio between the group and its home Wi-Fi on another channel. This mode isn't in the apps. It costs the laptop its normal Wi-Fi connection for the duration of the transfer, and that trade-off hasn't been settled.

## Troubleshooting

### "No Wi-Fi Direct device matching … was found"

The error lists the devices that were seen.

- DFTE has to be open on the phone, on the Send or Receive screen. The phone isn't discoverable anywhere else.
- Use the name the phone shows in its own Wi-Fi Direct settings. Matching is on that name or on the P2P address, both of which the error message lists.
- On Android 12 and older, the Location switch has to be on. The app shows a "Turn on Location for Wi-Fi Direct" row with a shortcut when it's off.
- Run `nmcli device` and check that a `p2p-dev-*` device exists. If it doesn't, your driver or NetworkManager build has no Wi-Fi P2P support.

### The connection times out after the device was found

Look at the phone. Samsung phones show an "Invitation to connect" dialog during negotiation, and nothing happens until someone taps Accept. dfte waits 60 seconds.

### The phone connects, then drops the group within seconds

The laptop probably became group owner without `dnsmasq` installed. Install it and try again.

### A stale `p2p-wlp…` interface after a crash

If dfte was killed while in a group, NetworkManager can keep a P2P client interface around and later attempts fail. This clears it:

```sh
nmcli radio wifi off && nmcli radio wifi on
```

That drops your normal Wi-Fi connection for a moment, too.

### The phone stops showing up after one transfer

After a group ends, Android sometimes reports that discovery is still running while the radio has actually stopped searching. The app stops and restarts discovery each time a Send or Receive screen opens, and clears a leftover group from an earlier run at startup. If the phone still doesn't show up, leave the screen and open it again.

### Transfers over the group are much slower than expected

See the 20 MHz limitation above. `iw dev <p2p interface> link` shows the negotiated rate on the laptop.

### `--wifi-direct` on other systems

`--wifi-direct` only exists on Linux. On other platforms it fails with a usage error.
