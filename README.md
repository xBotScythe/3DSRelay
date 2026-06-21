# 3DSRelay

[![build](https://github.com/xBotScythe/3DSRelay/actions/workflows/release.yml/badge.svg)](https://github.com/xBotScythe/3DSRelay/actions/workflows/release.yml)

A proof-of-concept offline messenger for the Nintendo 3DS. Nearby consoles exchange encrypted messages over local wireless (UDS ad-hoc) and relay them hop-by-hop, so a message can reach a recipient who isn't directly in range as long as a chain of devices connects them. It needs no internet, cell service, or access point.

The app presents itself on the Home Menu as a FAT32 disk diagnostics tool.

> This is an experimental project for learning and demonstration. The protocol is custom and has **not** been independently audited or reviewed. Don't rely on it where your safety depends on it. See [Limitations](#limitations) and the [threat model](THREAT_MODEL.md).

---

## Why?

Almost everything people use to talk to each other depends on infrastructure someone else controls: an access point, a cell tower, a server that can be unplugged, filtered, or surveilled. 3DSRelay is a proof-of-concept experiment in what's left when you remove all of that: devices that find each other directly over short-range radio and pass messages from hand to hand, with no account, no number, and no central point to block or seize.

The Nintendo 3DS is a deliberate choice, not a constraint. It is cheap, common, unremarkable to carry, and easy to disguise. This build hides as a disk-diagnostics tool, and its local wireless reaches far enough to chain devices into a mesh. The point isn't that the 3DS is a good secure-messaging platform (it has no secure element, so the disguise is cosmetic). The point is to build the whole stack: radio mesh, custom protocol, standard crypto primitives, and an honest accounting of where the trust boundaries actually sit on hardware nobody expects it on, and to be precise about what that does and does not buy you.

---

## Getting started

### Install

1. Copy `3DSRelay.cia` to the SD card and install it with FBI or another CIA installer.
2. Optionally copy a signed update package to `sdmc:/3ds/3DSRelay.update`. A device that holds one will seed it to nearby devices over the mesh.
3. It appears on the Home Menu as **FAT32 File System Diagnostics**.

### Unlock and set up identity

1. Launch **FAT32 File System Diagnostics**. It opens to a locked screen styled as a disk scanner.
2. Enter the unlock combination on the buttons (default: Up, Down, Up, Down, Left, Right). The combo is hashed and only checked once you've entered the full length, so the screen gives no feedback as you go.
3. Enter your alias. It is mixed into key derivation and is required every session.
4. Enter a passphrase. The alias and passphrase together derive your keypairs.

Your passphrase is never written to disk. The alias is stored in the config, and the identity seed is stored encrypted (it can only be decrypted with the key derived from your alias + passphrase). The derived keypairs themselves live only in RAM.

**Fumbled the combo?** Press **SELECT** to clear the in-progress entry. A wrong button stays in the buffer until the sequence reaches full length and then fails as a whole, so SELECT lets you start over cleanly. The entry also clears itself after 5 seconds of inactivity.

**Change the combo:** under **System Settings → Change Access Pattern**, press buttons to record a new sequence (up to 16), **START** to save, **SELECT** to cancel.

### Add a contact

Open **Add Contact** and **Scan QR Code** (point the outer camera at the other person's code). Show your own code under **Show My Public Key**, which also displays a short fingerprint you can read out to verify in person.

The QR code is a **signed contact card**: it carries the alias, the encryption key, and the signing key together with an Ed25519 signature, so a scanned card that is corrupted or whose keys don't belong together is rejected before it's added. This binds the keys to the identity but does not by itself defeat a substituted card: the in-person fingerprint check is still the defense. See the [threat model](THREAT_MODEL.md).

The handshake is mutual: a contact becomes usable only once **both** consoles have added each other. After you add someone they show as `[Pending]`; once their handshake arrives back the entry becomes `[Active]` and can be messaged. Handshakes are present in the background for a while, so the order in which you scan each other doesn't matter.

If someone adds you first, a **Contact Request** screen shows their alias and fingerprint: **A** to accept, **B** to reject. An unsolicited handshake registers nothing until you accept it.

### Messaging

- **Compose Private Msg** - pick a confirmed recipient under **Select Recipient**, then type. The message is encrypted so only that contact can read it. Pending contacts can't be selected.
- **Compose Broadcast Msg** - a signed, public message readable by everyone in range.
- Undelivered messages are held and relayed by intermediate consoles, so a recipient who isn't reachable now may receive a message later once a path exists. There is no delivery guarantee or acknowledgement.

### Updates

Updates are queried and transferred manually from nearby devices directly over the primary wireless link (Channel 1 UDS connection, multiplexed with chat data). This single-channel design avoids system prefetch abort crashes associated with secondary port binds. The client checks local SD versions first, downloading missing blocks only when a strictly newer update is available. Transfers are batched, resumable, and install automatically via AM services.

### Controls

| Context | Button | Action |
| --- | --- | --- |
| Locked | unlock combo | Enter the sequence to unlock |
| Locked | SELECT | Clear the in-progress combo |
| Any menu | D-pad Up/Down | Move selection |
| Any menu | A | Select / confirm |
| Submenu | B | Back |
| Main menu | START | Exit |
| Contact request | A / B | Accept / reject |
| QR scan | A / L / R | Capture a frame |
| QR scan | B | Cancel |
| Pattern setup | any buttons | Record (START save, SELECT cancel) |

With the lid closed the app keeps relaying: sleep is suppressed, the screens blank to save power, and it re-locks when the lid reopens.

### Clearing data

- **Three completed-but-wrong unlock attempts** clear the keys and contacts from RAM and force you to re-enter your passphrase. This does **not** delete anything from the SD card. Your encrypted identity and saved contacts are reloaded on the next successful unlock.
- **System Settings → Lock & Exit** zeroes the keys in RAM and closes the app, but leaves your encrypted contacts and message history on the SD card: they come back on the next unlock.
- **System Settings → Panic Wipe Staging** is the destructive one: it zeroes the keys in RAM *and* deletes the contacts file and packet cache from the SD card.

---

## How it works

### Mesh networking

Consoles find each other over UDS (Nintendo's local wireless) using a fixed comm ID. Packets propagate epidemically: each node stores what it receives and rebroadcasts it to peers it meets, and a TTL field caps the number of hops. Range is whatever UDS local wireless reaches (roughly tens of meters line-of-sight), extended only by relaying through other devices.

### Connection handling

The link is torn down only after several consecutive failed health checks rather than on a single bad read, so it survives brief radio gaps. A client that ends up alone in a network (its host vanished) treats that as a dead link and re-scans, or becomes a host itself, so an isolated console recovers on its own. The link is also serviced during long blocking operations such as a QR scan. A small random delay before each transmission reduces collisions when several consoles send at once.

### Rate limiting

Each packet carries a proof-of-work nonce whose SHA-256 hash must meet a difficulty target. The difficulty is intentionally low (mining averages only a few hundred hashes) so it stays fast on the hardware. It is a mild speed bump against flooding, not a serious anti-abuse mechanism. A signature cache rejects duplicate packets before the check runs.

### Cryptography

- **Primitives** come from TweetNaCl: Ed25519 signatures and `crypto_box` (Curve25519 + XSalsa20-Poly1305) for encryption. ChaCha20 with an HMAC-SHA256 tag protects data at rest. The *protocol* that combines them is custom.
- **Identity**: the alias and passphrase are run through PBKDF2-HMAC-SHA256 (25,000 iterations, which is a compromise for the 3DS's slow CPU, lower than current desktop recommendations) to derive a key that protects a random identity seed; the seed deterministically produces the Ed25519 and Curve25519 keypairs. Mixing the alias into derivation means a different alias yields different keys and fails the integrity check.
- **At rest**: the contacts file and the stored packet history are encrypted with a dedicated storage key (separate enc/MAC keys derived from the identity seed under their own labels, so the network keys are never reused for storage) and authenticated with encrypt-then-MAC. The packet store therefore loads only after unlock; broadcast text is no longer readable from a raw SD card.
- **Messages**: private messages use `crypto_box`; broadcasts and handshakes are signed with Ed25519. Update manifests are signed with a developer key whose public half is embedded in the app.
- **Contact trust**: the QR card is signed (alias, box key, and signing key, with an Ed25519 signature over alias + box key), so the scanner rejects a tampered or key-mismatched card. Adding a contact is still trust-on-first-use: a signed card proves internal consistency, not that the bearer is who they claim, so verify the fingerprint in person if it matters. A contact's alias is pinned to its key on first add and not overwritten afterward.

### OTA updates

`3DSRelay.update` is a signed manifest (version, payload size, SHA-256, Ed25519 signature) followed by the CIA payload. Updates are multiplexed over the main UDS connection (Channel 1) alongside normal chat packets, eliminating the unstable Port 2 network bind to prevent system prefetch abort crashes. The downloader requests blocks in batches; the seeder streams them from one open handle, paced for the receive queue. A per-block bitmap is saved next to the partial file so an interrupted transfer resumes from the missing blocks.

### Persistence

SD writes (config, contacts, packet cache) use a write-temp-then-rename pattern to avoid corruption from power loss or a crash. The contacts and packet stores are encrypted-then-MAC'd under the at-rest key; the contacts file is versioned, and an older file from a previous build is migrated to the new format on first unlock rather than discarded. The packet store loads at unlock and saves only while the keys are held, so relaying with the lid closed can't overwrite history with an empty buffer.

---

## Limitations

This is a proof of concept, not a hardened secure messenger. Known limits:

- **Not audited.** The cryptographic primitives are standard, but the surrounding protocol is custom and has had no external review.
- **Metadata is exposed.** It is not anonymous. Anyone in range can observe ciphertext, ephemeral keys, packet timing, and the sender of a broadcast. Epidemic relaying makes traffic analysis easier, not harder.
- **The unlock combo is weak.** It is a short button sequence with a small keyspace — a shoulder-surf/quick-lock deterrent, not a strong password. The 3-attempt RAM scrub limits online guessing but the secret itself is low-entropy.
- **Contact exchange is trust-on-first-use.** The QR card is signed, preventing raw tampering, but an attacker in physical range can still present their own signed card under your contact's alias. The fingerprint check is the only defense.
- **The disguise is cosmetic.** The name and icon present as a disk tool and the UI uses diagnostic-sounding labels, but anyone who gets past the lock sees a messenger. It is not steganographic or undetectable.
- **Rate limiting is light** (see above) and the PBKDF2 iteration count is modest for the hardware.
- **No delivery guarantees.** Messages may never arrive if no path forms before they age out of the relay buffers.

---

## Build

Requires devkitARM, libctru, and makerom.

```
make clean && make
```

Pack a signed update:

```bash
make update SIGNING_KEY=<private_key_hex>
```

This reads the version from source and produces `3DSRelay.update`.

### Distributing Your Own Updates

Consoles will only accept updates signed by the private key matching the public key hardcoded in the application binary. If you are fork-building the project and want to distribute your own updates:

1. Generate an Ed25519 keypair.
2. Replace the public key hex values in the `dev_pk_sign` array inside [source/crypto_utils.cpp](file:///Users/noahg/Documents/3dschat/source/crypto_utils.cpp#L707) with your own public key.
3. Build the application (`make`) and install the new `.cia` on the target consoles.
4. Pack your updates using your private key:
   ```bash
   make update SIGNING_KEY=<your_private_key_hex>
   ```

## Tests

The device-independent protocol mechanics (proof-of-work, packet signatures and dedup, compression, hashing, traffic-size uniformity) build and run on a host with no 3DS toolchain:

```bash
make -C tests test
```

By default, this runs a step-by-step visual propagation proof, simulating a 3-device relay network with animated proof-of-work mining, TTL decrements, payload decompression, and loop prevention validation.

You can also run in interactive mode to test custom payloads and toggle packet tampering:
```bash
make -C tests test ARGS="-i"
```

CI runs these tests on every push. They cover the wire logic only: the radio layer, camera/QR capture, and on-device key handling still need real hardware. See the [threat model](THREAT_MODEL.md) for what is and isn't covered.

## Development

This is an ongoing project. Please report any bugs you find.

## Credits

- [TweetNaCl](https://tweetnacl.cr.yp.to/)
- [Smaz](https://github.com/antirez/smaz)
- [QR Code generator](https://www.nayuki.io/page/qr-code-generator-library)
- [quirc](https://github.com/dlbeer/quirc)
- [devkitARM](https://devkitpro.org/) / [libctru](https://github.com/devkitPro/libctru)
