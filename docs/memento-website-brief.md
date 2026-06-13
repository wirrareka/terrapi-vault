# Memento — website presentation brief (for the web designer)

A brief for building the **Memento** showcase/landing section on the Terrapi website. Everything
here is grounded in the actual product/tech (the `terrapi-vesta` library + `vesta-sync` that Memento
is built on). **Do not invent security claims** — the wording below is what we can stand behind.
Flag anything you'd like reworded; marketing owns final copy, this is the accurate substrate.

---

## 1. What Memento is (the one-liner)

> **Memento — private notes that stay yours. End-to-end encrypted, on every device.**

Memento is a personal **notes app** with multi-device sync where the sync server **never sees your
notes**. Your notes are encrypted on your device with a key only you hold; the cloud only ever
stores opaque ciphertext. Built on Terrapi's open, audited encryption.

**Audience:** privacy-conscious individuals + developers/power-users who want notes that are genuinely
private (not "we promise not to look") and that work seamlessly across their devices.

---

## 2. Core message & pillars

Lead with **trust through design, not promises**. Three pillars:

1. **End-to-end encrypted — the server is blind.** The sync server stores only opaque encrypted
   blobs + device public keys. It never sees your passphrase, your key, or your note text.
2. **Your key never leaves your device.** Notes are encrypted at rest with 256-bit AES; the key is
   derived from your passphrase with Argon2id and is held only in memory, wiped when you lock.
3. **Open & verifiable.** The encryption format is publicly documented (precise enough for an
   independent implementation) and the library is open-source — not a black box.

---

## 3. Feature highlights (all factual — safe to put on the page)

| Feature | One-line copy | Detail (for tooltips / "learn more") |
|---|---|---|
| End-to-end encryption | "The server never sees your notes." | Content syncs as AEAD ciphertext; the server stores `vault_id`, device public keys, and opaque ops only. |
| Strong at-rest crypto | "256-bit AES, locked with Argon2id." | SQLCipher 4, AES-256 + HMAC-SHA512; key = Argon2id (64 MiB / 2 passes) — deliberately slow to brute-force. |
| Key never on disk | "Your key lives only in memory." | Derived key held in a zeroizing secret box, wiped on lock/drop; disk holds only a salt + KDF params (no secrets). |
| Multi-device, live sync | "All your devices, instantly in sync." | Row-level oplog; live updates over a WebSocket tail; conflicts resolved per-row (last-writer-wins / CRDT) on-device. |
| Device-keypair security | "Each device proves itself — no passwords on the wire." | Every sync call is signed by the device's ed25519 key; replay-protected (time window + one-time nonces). |
| Recovery codes | "Lose your password, not your notes." | A 160-bit recovery code is an independent unlock slot; changing your passphrase never invalidates it. |
| Open format | "Documented, dual-licensed, independently verifiable crypto." | On-disk format spec is CC-BY-4.0; the library is MIT/Apache-2.0, `#![forbid(unsafe_code)]`. |

---

## 4. Suggested page structure (sections)

1. **Hero** — the one-liner headline + a sub-line + primary CTA (download / get Memento) + a calm
   product visual (a note, a small lock motif). Keep it spacious.
2. **The promise (3 pillars)** — three cards from §2 (blind server / key on device / open & verifiable),
   each with a short line + small icon.
3. **How it works** — a simple 3-step diagram: *write on your device → it's encrypted locally →
   syncs as ciphertext to your other devices.* Emphasize the server box is "blind" (can't read).
   (Optional: a "server's view" vs "your view" split — server sees gibberish, you see your note.)
4. **Security, in plain words** — short, honest section: what E2E means, the recovery code, the open
   format link. Link to the format spec for the technical crowd (credibility).
5. **Features grid** — the table in §3 as a clean grid.
6. **FAQ** — "Can Terrapi read my notes?" (No.) "What if I forget my password?" (Recovery code.)
   "What if I lose a device?" (Its key is just removed; data stays encrypted.) "Is it open source?" (Yes.)
7. **CTA footer** — get Memento + a link to the open spec / GitHub for the technically curious.

---

## 5. Tone & visual direction

- **Tone:** calm, precise, confidence without hype. Privacy framed as *the default*, not a feature
  you pay extra for. Avoid fear-mongering; avoid over-claiming.
- **Visual:** minimal and trustworthy — think Linear / Notion / Stripe restraint. Generous whitespace,
  one accent color, crisp typography, subtle lock/key/shield motifs (don't overdo padlock clichés).
  Light + dark both look good (the product itself supports dark).
- **Imagery for "blind server":** the strongest concept — show the same note as *readable on the
  user's device* and *unreadable ciphertext on the server*. That single visual sells the whole story.

---

## 6. Honest constraints (so copy stays accurate — important)

- E2E protects **note content**. Some **metadata** (number/size/timing of changes, device public keys,
  a collection id) is visible to the sync server unless its own at-rest encryption is enabled, and
  transport is protected by TLS. So say **"the server can't read your notes,"** not "the server knows
  literally nothing." Don't claim anonymity or metadata-hiding we don't provide.
- Don't claim specific platforms, pricing, app-store presence, or UI specifics here — those aren't
  settled in this material; marketing/product fills them. This brief covers the **what + the security
  story**, which is the part that must be accurate.

---

## 7. Ready-to-use copy snippets (all grounded)

- "Private notes that stay yours."
- "End-to-end encrypted — the server never sees your notes."
- "256-bit encryption. Your key never leaves your device."
- "All your devices, always in sync — without trusting the cloud."
- "Lose your password, not your notes."
- "Open, documented encryption — verify it yourself."

---

## 8. Credibility links (for the technical reader / footer)

- On-disk encryption format spec (open, CC-BY-4.0): `terrapi-vesta/spec/vault-format.md`
- Sync protocol (server-blind design): `terrapi-vesta/spec/sync-openapi.yaml`
- Library source (open, dual-licensed): the `terrapi-vesta` repository

> Source of these facts: `terrapi-vesta` `spec/vault-format.md` (§1, §3, §13), `spec/sync-openapi.yaml`,
> `docs/sync-bootstrap.md`, and the library/sync source. If anything above changes, re-confirm before
> publishing.
