# 3DSRelay

An offline, internet-free mesh messenger for the Nintendo 3DS. Nearby consoles pass encrypted messages to each other over local wireless (UDS ad-hoc), and messages hop from device to device until they reach the intended recipient. Broadcasts reach everyone in range. The whole thing runs without cell towers, routers, or internet access.

The app is disguised as a FAT32 disk diagnostics tool.

---

## Getting started

### Install

1. Copy `3DSRelay.cia` to the SD card and install it with FBI or your preferred CIA installer.
2. Copy the signed update package `3DSRelay.update` to the `/3ds` folder on the SD card (i.e., `sdmc:/3ds/3DSRelay.update`). Placing it here allows the console to serve/seed the update package to other nearby devices over the local mesh network.
3. It shows up on the Home Menu as **FAT32 File System Diagnostics**.

### Unlock and set up identity

1. Launch **FAT32 File System Diagnostics**. It opens in a locked state disguised as a disk scanner.
2. Enter the unlock combination on the buttons (default: Up, Down, Up, Down, Left, Right). The combo is hashed and compared only once you've entered the full length, so nothing on screen hints at progress.
3. Enter your alias. This is part of your cryptographic identity and is required every session.
4. Set a master passphrase. The alias and passphrase together derive your keypair in RAM. Neither is stored on disk.

**Fumbled the combo?** Press **SELECT** to clear the in-progress entry and start over. A wrong button stays in the buffer until the sequence reaches full length and then fails as a whole — and a completed-but-wrong attempt counts toward the panic wipe — so SELECT lets you reset cleanly without burning an attempt. The entry also resets on its own after 5 seconds of inactivity, so you can take your time.

**Panic wipe:** three completed-but-wrong unlock attempts zero your keys from RAM and clear the contact list. The same wipe can be triggered deliberately from **System Settings → Panic Wipe Staging**, which also shreds contacts and the packet cache on the SD card.

**Change the combo:** under **System Settings → Change Access Pattern**, press any buttons to record a new sequence (up to 16 presses), **START** to save, or **SELECT** to cancel.

### Add a contact

Open **Add Contact** and either **Scan QR Code** (point the outer camera at the other person's code) or **Enter Key Manually** (type their alias and 64-char public key hex). Show your own code from **Show My Public Key**, which also displays your key fingerprint for in-person verification.

The handshake is mutual — a contact only becomes usable once **both** consoles add each other. After you add someone you'll see them as `[Pending]`; once their reciprocal handshake arrives the entry flips to `[Active]` and can be messaged. Handshakes are resent periodically in the background, so the order in which the two of you scan doesn't matter.

If someone adds you first, a **Contact Request** screen appears showing their alias and fingerprint: press **A** to accept (registers and confirms them) or **B** to reject. Nothing is registered from an unsolicited handshake until you accept.

### Messaging

- **Compose Private Msg** — pick a confirmed recipient under **Select Recipient**, then type to send a `crypto_box`-encrypted message only they can read. Pending contacts can't be selected until the handshake completes.
- **Compose Broadcast Msg** — a signed public announcement visible to every node in range.
- Messages that can't be delivered yet are stored and forwarded through intermediate consoles automatically, so a recipient who is out of range now receives them once a path exists.

### Updates

Updates propagate between consoles over the mesh, no internet required. A console that holds a newer signed package seeds it to nearby devices, which verify the manifest signature and payload hash before installing through the system AM service.

The app checks for staged updates at startup and via **Check for Updates** in settings. Transfers are **windowed** (many blocks per request instead of one-at-a-time) and **resumable** — if the link drops mid-download, progress is saved and the next check continues from where it left off rather than restarting, and the transfer re-acquires a peer automatically if one disappears.

### Controls

| Context | Button | Action |
| --- | --- | --- |
| Locked | unlock combo | Enter the sequence to unlock |
| Locked | SELECT | Clear the in-progress combo |
| Any menu | D-pad Up/Down | Move selection |
| Any menu | A | Select / confirm |
| Submenu | B | Back to the previous screen |
| Main menu | START | Exit the app |
| Contact request | A / B | Accept / reject |
| QR scan | A / B | Capture a frame / cancel |
| Pattern setup | any buttons | Record sequence (START save, SELECT cancel) |

The mesh keeps relaying with the lid closed: sleep is suppressed, the screens blank to save power, and the app re-locks when you reopen the lid.

---

## Technical details

### Mesh networking

Consoles discover each other over UDS (Nintendo's local wireless protocol) using comm ID `0x48425710`. Packets propagate epidemic-style: every node stores what it receives and rebroadcasts to new peers. A TTL field caps the hop count.

Routing runs while the app is open. Sleep mode is disabled so the console stays connected with the lid closed.

### Connection resilience

A strike-based teardown replaces the default behavior of dropping the link on a single bad read. The connection survives brief radio gaps (walking past each other, momentary interference) and only tears down after 5 consecutive health check failures. A client that has lost its host (only itself left in the network) is detected as a dead link and re-scans to reconnect or, failing that, becomes a host itself, so an isolated console recovers on its own. The mesh is also serviced during long blocking operations such as a QR scan, so the link is not starved while the camera is open.

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

Transfers are windowed: the downloader requests a batch of blocks and the seeder streams them back-to-back (paced to respect the receive queue) instead of one round trip per block. A per-block bitmap is written alongside the partial file, so an interrupted download resumes from the missing blocks instead of starting over, and the downloader re-acquires any peer advertising the same version and hash if the original seeder drops. The wire format is unchanged, so the seeder still answers legacy single-block requests from peers running the old protocol.

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
