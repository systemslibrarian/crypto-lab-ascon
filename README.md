# crypto-lab-ascon

## What It Is
Browser-based demo of Ascon, the NIST Lightweight Cryptography Standard (FIPS SP 800-232, 2025). It implements Ascon-AEAD128 authenticated encryption and Ascon-Hash256 from the specification using real bitwise arithmetic with no external crypto libraries. All 64-bit operations use BigInt for precision. The sponge construction, S-box, and linear diffusion layer are implemented directly from the spec and verified against official KAT vectors. The interactive sponge exhibit renders the actual 320 bits of live state — every square is a real bit — so you can watch the permutation diffuse the state toward ~50% density rather than trusting a decorative bar.

## When to Use It
- Understanding why NIST needed a lightweight standard beyond AES.
- Teaching sponge-based cryptography vs block/stream ciphers.
- Comparing side-channel resistance profiles in constrained devices.
- Evaluating Ascon for IoT and embedded deployments.
- Not for high-throughput server encryption where AES-GCM hardware acceleration is available.
- Do NOT use this BigInt-based browser build as production crypto — it is a teaching demo, not a hardened native implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-ascon](https://systemslibrarian.github.io/crypto-lab-ascon/)**

Run Ascon-AEAD128 encryption and Ascon-Hash256 in the browser and watch the interactive sponge exhibit render all 320 bits of live state, where every square is a real bit diffusing toward ~50% density as the permutation runs.

## What Can Go Wrong
- 128-bit keys provide a smaller long-term margin than AES-256.
- BigInt in browsers is slower than native 64-bit C/Rust implementations.
- Ascon has less historical cryptanalysis depth than AES, even as a finalized NIST standard.
- Nonce reuse breaks the AEAD guarantees, as with any nonce-based authenticated cipher.

## Real-World Usage
- NIST FIPS SP 800-232 was finalized in 2025 after the Lightweight Cryptography competition.
- Ascon was selected in February 2023 from 57 original submissions.
- Early adoption targets include automotive in-vehicle networks, RFID authentication, and industrial IoT sensors.
- Further targets include smart-card communications and embedded firmware verification pipelines.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-ascon
cd crypto-lab-ascon
npm install
npm run dev
```

## Related Demos
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES modes and AEAD for comparison with lightweight crypto.
- [crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/) — high-performance AES-based AEAD.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ARX stream cipher used in lightweight contexts.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — modern hash functions including sponge-based SHA3.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — hash constructions including Merkle-Damgård and sponge.

## Build & Verify
```bash
npm install
npm test     # 16 tests, incl. the full official NIST AEAD + Hash KAT vector files
npm run build
npm run dev  # local dev server
```
Correctness is the headline: `test/kat-full.test.ts` runs every vector in the official `LWC_AEAD_KAT_128_128.txt` and `LWC_HASH_KAT_128_256.txt` files through encrypt, decrypt, and hash, and `test/permutation.test.ts` checks `p12` against the ascon-c reference output. `test/roundtrip.fuzz.test.ts` adds randomized round-trip, single-bit-tamper, and full block-boundary (length 0–40) coverage. The GitHub Pages deploy is gated on these tests passing, so a broken implementation never ships.

## Performance
This implementation optimizes for legibility, not throughput: all 64-bit operations use `BigInt`, which V8 boxes on the heap. Measured ~1.7 MB/s for AEAD and ~0.5 MB/s for hashing in Node — fine for an interactive demo, but native C/Rust Ascon (using machine 64-bit words) runs orders of magnitude faster, and `crypto.subtle` AES-GCM on AES-NI hardware reaches multiple GB/s. The point of Ascon is small code and state on constrained devices, not raw speed on a desktop CPU.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
