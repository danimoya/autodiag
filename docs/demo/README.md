# Demo recording

`autodiag.gif` is the terminal animation for the repository README. It is a real
terminal session: the CLI lists the ADR problems of a target and diagnoses one of
them end to end (evidence collection, model assessment, verified proofs). Only the
keystrokes and the pacing of the output are simulated.

Play the recording in a terminal:

```bash
asciinema play docs/demo/autodiag.cast        # add -s 2 to double the speed
```

Regenerate it against your own target (asciinema 2.x and agg required):

```bash
DEMO_TARGET=mydb DEMO_PROBLEM_KEY='ORA 600 [kkslgop1]' \
AGG=~/.cargo/bin/agg AGG_FONT_DIR=/usr/share/fonts/jetbrains-mono \
docs/demo/make.sh
```

`make.sh` records `record.sh` at 100x32 with idle time capped at 2 seconds, strips the
local home path and hostname from the cast, then renders the GIF. The cast is a text
file and is covered by the repository hygiene scan.
