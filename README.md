# crypto-lab-ascon

## What It Is
Browser-based demo of Ascon, the NIST Lightweight Cryptography Standard (FIPS SP 800-232, 2025). It implements Ascon-AEAD128 authenticated encryption and Ascon-Hash256 from the specification using real bitwise arithmetic with no external crypto libraries. All 64-bit operations use BigInt for precision. The sponge construction, S-box, and linear diffusion layer are implemented directly from the spec and verified against official KAT vectors.

## When to Use It
- Understanding why NIST needed a lightweight standard beyond AES.
- Teaching sponge-based cryptography vs block/stream ciphers.
- Comparing side-channel resistance profiles in constrained devices.
- Evaluating Ascon for IoT and embedded deployments.
- Not for high-throughput server encryption where AES-GCM hardware acceleration is available.

## Live Demo
https://systemslibrarian.github.io/crypto-lab-ascon/

## What Can Go Wrong
- 128-bit keys provide a smaller long-term margin than AES-256.
- BigInt in browsers is slower than native 64-bit C/Rust implementations.
- Ascon has less historical cryptanalysis depth than AES, even as a finalized NIST standard.

## Real-World Usage
NIST FIPS SP 800-232 was finalized in 2025 after the Lightweight Cryptography competition. Ascon was selected in February 2023 from 57 original submissions. Early adoption targets include automotive in-vehicle networks, RFID authentication, industrial IoT sensors, smart-card communications, and embedded firmware verification pipelines.

> "Whether therefore ye eat, or drink, or whatsoever ye do, do all to the glory of God."
> - 1 Corinthians 10:31
