# Seeds

Utility to generate the seeds.txt list that is compiled into the client
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

Be sure to update `PATTERN_AGENT` in `makeseeds.py` to include the current version,
and remove old versions as necessary (at a minimum when GetDesirableServiceFlags
changes its default return value, as those are the services which seeds are added
to addrman with).

The seeds compiled into the release must be Blackcoin / Blackcoin peers,
not Bitcoin peers. Update `nodes_main.txt` and `nodes_test.txt` from trusted
long-lived Blackcoin nodes or from a Blackcoin seed crawler, then regenerate
the header from the `/contrib/seeds` directory:

```
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```

If a future crawler emits a Core-style `seeds.txt`, filter it with
`makeseeds.py` first and then review the resulting node list before regenerating
`src/chainparamsseeds.h`.
