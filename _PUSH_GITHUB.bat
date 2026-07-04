@echo off
REM ============================================================
REM  Push Sim-OS hardening (external audit fixes P0-1..P1-6)
REM ============================================================
cd /d "%~dp0"
echo.
echo === Staging ===
git add -A
echo.
echo === Commit ===
git commit -m "harden Sim-OS per external audit: full content-hash spec_id (P0-1), replication-gated canon promotion (P0-2), real state-restoring rollback (P0-3), fail-closed memory plane (P0-4), rehydrate canon pointer (P1-5), enforce operator canon (P1-6); honest README claims"
echo.
echo === Push ===
git push origin master
echo.
echo === Done. https://github.com/bitmaster162/continuityos ===
echo.
pause
