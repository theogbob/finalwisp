# server/fuzz/regress: fuzz regression inputs

One directory per fuzz target. Every file is an input the fuzzer kept (new coverage) or a crash seed that was fixed;
`wst compat --fuzz-replay` replays them all on every gate. The files are fuzzer-made bytes.

Some files in ext-records/ contain the text "PRIVATE KEY" (78 at the time of writing): the fuzzer mutates the PEM
headers that the key-auth parser looks for. They are random bytes, not keys, and none of them is a usable key or
certificate. Secret scanners will flag them; that is expected.
