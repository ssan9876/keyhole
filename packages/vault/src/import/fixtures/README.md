# Import fixtures

One sample export per format Keyhole detects.

**No file here contains a real credential.** Every one was generated: the
passwords are literals beginning `fixture-pw-`, the accounts are `example.com`
and `example.org`, and the identifiers are runs of a single digit. Each fixture
also carries the sentence

> GENERATED FIXTURE - no real credential appears in this file

inside itself — in the free-text column of its first row for the CSVs, in the
first item's note for the JSON exports, and as `KEYHOLE-FIXTURE-NOTICE.txt`
inside the `.1pux` archive. CSV has no comment syntax, so the notice cannot sit
above the header line without becoming the header line; the notes column is the
closest a CSV gets to a comment while remaining a valid export.

## What each fixture claims to be

`detect.test.ts` holds the authoritative table. The important thing to know
before adding one: **the header line is the thing under test.** A fixture whose
header was guessed from documentation rather than taken from a real export tests
the documentation, and every parser built against it inherits the guess. The
report in `.superpowers/sdd/task-2-report.md` records, per fixture, whether its
header line came from a vendor's own source code, from vendor documentation, or
from a weaker source — replace the weak ones with bytes from a real export when
one is available.

## The three that are not straightforwardly "a format"

- `chrome-passwords.csv`, `microsoft-edge-passwords.csv` and
  `brave-passwords.csv` are **byte-identical**, deliberately. All three ship
  Chromium's exporter unchanged, so nothing but the filename separates them, and
  a test asserts the three files still have identical bytes.
- `keeper-export.csv` has **no header row** — that is what Keeper's CSV export
  looks like. It is therefore not content-detectable and is expected to fall
  through to the generic mapper, which is what its test asserts.
- `unknown-manager-export.csv` is not any real product. It stands for every
  manager nobody anticipated, and its test is that detection routes it to the
  generic mapper instead of failing.
