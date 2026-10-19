Source: https://github.com/ahenzinger/simplepir
Pinned revision: e9020b03bf2872c75b8954e749e32408b5db87ed
License: upstream/LICENSE (MIT).
Only upstream modification: remove -march=native from three CGO flags for portable Apple Silicon compilation. The adapter derives public A from a seed using a separate local expander; it does not reset the upstream private PRG to a public seed. Queries are generated in a separate client process with fresh OS-seeded randomness. No security parameters were reduced: n=1024, logq=32, upstream parameter table.
