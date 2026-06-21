# 3DSRelay

An offline, internet-free mesh messenger for the Nintendo 3DS. Nearby consoles pass encrypted messages to each other over local wireless (UDS ad-hoc), and messages hop from device to device until they reach the intended recipient. Broadcasts reach everyone in range. The whole thing runs without cell towers, routers, or internet access.

The app is disguised as a FAT32 disk diagnostics tool.

---

## Getting started

### Install

1. Copy `3DSRelay.cia` to the SD card.
2. Install it with FBI or your preferred CIA installer.
3. It shows up on the Home Menu as **FAT32 File System Diagnostics**.

### Unlock and set up identity

1. Launch **FAT32 File System Diagnostics**.
2. Enter the unlock combination on the D-pad (default: Up, Down, Up, Down, Left, Right).
3. Enter your alias. This is part of your cryptographic identity and is required every session.
4. Set a master passphrase. The alias and passphrase together derive your keypair in RAM. Neither is stored on disk.

### Add a contact

Show your QR code and have the other person scan it, or enter their public key hex manually. Both consoles need to complete the exchange. Contacts show as `[Pending]` until the reciprocal handshake arrives, then `[Active]`.

### Messaging

- Select a contact and type to send an encrypted private message.
- Broadcasts are signed public announcements visible to all nodes.
- Messages that can't be delivered yet get stored and forwarded through intermediate consoles automatically.

### Updates

Updates propagate between consoles over the mesh, no internet required. Verified update packages are installed through the system AM service. The app checks for staged updates at startup and via the Check for Updates option in settings.

Entering the wrong unlock sequence 3 times triggers a panic wipe: keys are zeroed from RAM and contacts/packets are shredded on the SD card.

---

## Technical details

### Mesh networking

Consoles discover each other over UDS (Nintendo's local wireless protocol) using comm ID `0x48425710`. Packets propagate epidemic-style: every node stores what it receives and rebroadcasts to new peers. A TTL field caps the hop count.

Routing runs while the app is open. Sleep mode is disabled so the console stays connected with the lid closed.

### Connection resilience

A strike-based teardown replaces the default behavior of dropping the link on a single bad read. The connection survives brief radio gaps (walking past each other, momentary interference) and only tears down after 5 consecutive health check failures.

A randomized 1-5ms jitter before each transmission reduces collisions when multiple consoles try to broadcast at the same time.

### Spam suppression

Every packet requires a proof-of-work nonce: the sender finds a value that makes the SHA-256 hash of the packet meet a difficulty target. Mining runs asynchronously at 3000 hashes per frame so the UI stays responsive.

An FNV-1a signature cache (computed over immutable packet fields, excluding TTL) rejects duplicates before the PoW check runs.

### Cryptography

- **Identity derivation**: the alias and passphrase are concatenated and run through PBKDF2-HMAC-SHA256 to produce a 32-byte identity seed. That seed deterministically generates an Ed25519 signing keypair and a Curve25519 box keypair via TweetNaCl. Keys only exist in RAM. Because the alias is part of the KDF input, changing it produces entirely different keys.
- **Encryption**: private messages use `crypto_box` (Curve25519 + XSalsa20-Poly1305). The identity seed and contact records are encrypted at rest with ChaCha20.
- **Signatures**: broadcasts and handshakes are signed with Ed25519. Update manifests are signed with the developer key.
- **Alias binding**: the alias is cryptographically inseparable from the identity. It is entered every session and used as KDF input alongside the passphrase. Entering a different alias produces different keys and fails the MAC check. Contact aliases are pinned to their public keys on first add and cannot be overwritten.

### OTA updates

The update file (`3DSRelay.update`) has a signed manifest header (magic, version, payload size, SHA-256 hash, Ed25519 signature) followed by the CIA payload. The app re-verifies the signature and hash before installing through the system AM service.

### Persistence

All SD card writes (config, contacts, packet cache) use an atomic pattern: write to a `.tmp` file, flush, close, then rename over the target. Prevents corruption from unexpected power loss or crashes.

### Build

Requires devkitARM, libctru, and makerom.

```
make clean && make
```

To pack a signed update:

```
make update SIGNING_KEY=<private_key_hex>
```

Reads the version number from source and produces `3DSRelay.update`.

### Credits

- [TweetNaCl](https://tweetnacl.cr.yp.to/) — Daniel J. Bernstein et al. (public domain)
- [Smaz](https://github.com/antirez/smaz) — Salvatore Sanfilippo (BSD)
- [QR Code generator](https://www.nayuki.io/page/qr-code-generator-library) — Project Nayuki (MIT)
- [quirc](https://github.com/dlbeer/quirc) — Daniel Beer (ISC)
- [devkitARM](https://devkitpro.org/) / [libctru](https://github.com/devkitPro/libctru) — devkitPro team
