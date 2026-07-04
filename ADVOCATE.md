# Devil's Advocate — the rubric every move is checked against

ContinuityOS runs consequential claims and actions through this rubric *before*
they are accepted (`cos advocate "<claim>" [--action]`). Deterministic checks run
against your own memory; the rest are questions you must answer. The verdict and
flags are recorded append-only to the `audit` namespace.

| # | Angle | The skeptic asks | Auto-detector |
|---|---|---|---|
| 1 | contradiction | Does memory directly contradict this? | overlap + opposite polarity / success-vs-failure |
| 2 | staleness | Is this built on a superseded fact? | overlapping source has `superseded_by` |
| 3 | evidence | Recorded evidence, or just assertion? | best keyword overlap in recall |
| 4 | canon | Conflicts with a non-negotiable rule? | `twin.alignment()` |
| 5 | overconfidence | Absolutes (always/never/100%) without proof? | absolute regex minus hedges |
| 6 | honesty | Only wins, failures omitted? (canon) | positive claim with no failure/limit word |
| 7 | reversibility | Irreversible action? | delete/publish/send/rotate/deploy/pay verbs |
| 8 | alternatives | Strongest alternative, and why not it? | (answer) |
| 9 | assumptions | What must be true? Verified? | (answer) |
| 10 | blast_radius | Who/what breaks if this is wrong? | (answer) |

**Verdicts:** STOP (high flag on contradiction/canon/irreversible-action) ·
RECONSIDER (other high flag) · PROCEED WITH CAUTION (medium flags) · PROCEED.

**Limitation (honest):** the contradiction detector is a keyword-overlap heuristic —
it needs ≥2 shared terms with the contradicting memory to fire. It complements, not
replaces, human judgment. `cos audit --devil` runs this over every failing finding.
