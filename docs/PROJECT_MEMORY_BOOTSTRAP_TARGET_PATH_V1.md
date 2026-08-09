# Project Memory Bootstrap Target Path v1 (R40)

R40 closes a target-path authority-binding defect in the R38 fresh project-memory bootstrap.

R38 authorization binds an exact `target_db`. Before R40, the bootstrap rejected a symlink or reparse point only when the immediate parent itself was such an object. A lexical target could therefore traverse a symlinked ancestor while the final parent directory appeared ordinary. Publication then followed the lexical pathname and could create the database under a different physical parent than the authorization text implied.

R40 requires the existing target parent to resolve to the same path as its lexical absolute form. Any symlink, junction, or reparse traversal in the target parent ancestry is refused before manifest authorization validation, temporary SQLite creation, or publication.

The historical R38 bootstrap implementation remains byte-unchanged. A stdlib-only lazy post-import guard strengthens only its `_safe_parent` boundary, so both the CLI and direct Python API receive the same invariant without eager-loading the bootstrap module.

The bootstrap effect and authority ceilings are otherwise unchanged: fresh shadow memory only, no overwrite, no accepted-truth mutation, no canonical-state mutation, no deployment, no agent dispatch, `can_trade=false`, and `capital_permission=DENY`.
