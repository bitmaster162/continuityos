# Work Ledger ↔ Candidate Review Binding Gate v1

This gate binds exact Work Admission, Work Delta, host transport, GPT semantic
decision, immutable ledger bytes, exact ledger projection and Candidate Review
evaluation to one repository, task, candidate branch, HEAD and tree.

It rejects stale projections, hash-chain mutation, receipt substitution,
projection/review equivocation and review of another remote candidate. The
candidate-review evaluation is recomputed from its raw five inputs; a supplied
PASS JSON is not trusted by itself.

A PASS is still proposal-only and does not merge or apply state.
