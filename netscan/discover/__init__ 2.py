"""Ways of finding out what a device is: mDNS, SSDP/UPnP, NetBIOS, TTL, service banners and DHCP requests.

Probes only ever talk to devices inside the allow-list (or to link-local multicast groups that never leave
the LAN), read-only, and everything they hear is cleaned before it is stored or shown.
"""
