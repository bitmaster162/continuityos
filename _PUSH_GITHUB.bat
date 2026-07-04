@echo off
REM ============================================================
REM  PR-7: gate runner polish (GPT re-audit) — fix shorthand
REM  first-token loss + WARN shell parity + regression tests.
REM ============================================================
cd /d "%~dp0"
echo.
echo === Staging ===
git add -A
echo.
echo === Commit ===
git commit -m "PR-7: fix gate runner — shorthand preserves first token, WARN keeps shell semantics; add regression tests (GPT audit)"
echo.
echo === Push ===
git push origin master
echo.
echo === Done. https://github.com/bitmaster162/continuityos ===
echo.
pause
