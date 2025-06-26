# Low Latency Cryptography Areion (Rust Implementation)

## About

This software provides a reference code of the low-latency cryptographic permutation algorithm Areion by Rust and includes applications such as hashing and AEAD processing mode OPP. It should be noted that this software is provided as a reference and has not been optimized.

For more information on Areion, visit: https://eprint.iacr.org/2023/794

## Support Architecture

To run this software, the following environmental requirements are necessary.

- Ubuntu 24.04
- SIMD
- x86-64 architecture (with AES-NI support)

## How to Build

```
$ sudo apt install --no-install-recommends gcc g++
$ export RUSTFLAGS='-C target-feature=+aes'
$ cargo build --release
```

## How to Test

```
$ cargo test
```

# License

The source code is copyright (c) GMO Cybersecurity by Ierae, Inc., and provided under the MIT license.
The full text is included in the file LICENSE.txt.

## Reference

The cryptographic algorithms implemented in this software were proposed in the following research paper.

```
@misc{cryptoeprint:2023/794,
      author = {Takanori Isobe and Ryoma Ito and Fukang Liu and Kazuhiko Minematsu and Motoki Nakahashi and Kosei Sakamoto and Rentaro Shiba},
      title = {Areion: Highly-Efficient Permutations and Its Applications (Extended Version)},
      howpublished = {Cryptology ePrint Archive, Paper 2023/794},
      year = {2023},
      doi = {10.46586/tches.v2023.i2.115-154},
      note = {\url{https://eprint.iacr.org/2023/794}},
      url = {https://eprint.iacr.org/2023/794}
}
```
