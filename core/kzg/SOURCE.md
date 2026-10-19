# EIP-4844 KZG trusted setup (structured reference string)

`trusted_setup_4096.txt` is the output of Ethereum's KZG setup ceremony as distributed by c-kzg-4844
(4096 G1 Lagrange points, 65 G2 monomial points, 4096 G1 monomial points).

- sha256 `d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7` (pinned in `core/oobsvc/kzg.py`;
  loading any other file raises).
- Distributed in the PyPI sdist `ckzg-2.1.8.tar.gz` (`src/trusted_setup.txt`). The same bytes were
  fetched from `https://raw.githubusercontent.com/ethereum/c-kzg-4844/main/src/trusted_setup.txt` (identical sha256).
- Cross-check: every point equals the corresponding entry of the consensus-specs mainnet preset
  `presets/mainnet/trusted_setups/trusted_setup_4096.json` (fetched from github.com/ethereum/consensus-specs, master;
  sha256 of that JSON `f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f`): g1_lagrange, g2_monomial and
  g1_monomial all equal.
- No locally generated SRS is used anywhere in this repository (not even in unit tests).
- Assumption (paper App. A): nobody knows the ceremony trapdoor (secure if one contributor destroyed its share).
