# JIT (for WireGuard)

Inserts a BPF filter that filters for UDP packets to the WireGuard port. 
If detected, it sends the packet to userland. Then, it filters for 
the handshake Initiator packets and extracts the static public key 
after deriving the shared key.

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.

## Purpose

I saw this article on [HN](https://news.ycombinator.com/item?id=39688545) 
about [Wireguard JIT](https://fly.io/blog/jit-wireguard-peers/). I 
thought this would be really useful but I couldn't find the source 
code online.

Luckily, it was described in words so of course I turned it into code.

I actually saw this earlier, but I was giving a talk at the Handycon
conference so I was nervous and dealing with that.

Sorry if anyone was trying to figure this out!

## Notes

I got all the Noise code from [wireguard-go](https://github.com/WireGuard/wireguard-go/) and copy pasted it at the bottom.

## How to Use

1. Get Go

2. Install the modules listed in the import

3. Then you can just run it
```
go run wg.go -privatekey KEY -port PORT -iface INTERFACE
```

PORT is optional, but KEY and INTERFACE must be there. INTERFACE is like eth0 or enp2s50 and KEY is like "base64-encoded-wireguard-private-key"

## Copyright

Copyright (c) 2024 Andrew Lee <andrew@joseon.com>

All Rights Reserved

MIT Licensed
