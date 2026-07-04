@echo off
REM ============================================================
REM  Push ContinuityOS: add THREAT_MODEL.md (fixes broken README
REM  link) — the honest edge doc a Show HN audience looks for.
REM ============================================================
cd /d "%~dp0"
echo.
echo === Staging all changes ===
git add -A
echo.
echo === Commit ===
git commit -m "docs: add THREAT_MODEL.md (fix broken README link) — honest trust boundaries, agents-propose-deterministic-disposes"
echo.
echo === Push ===
git push origin master
echo.
echo === Done. Check: https://github.com/bitmaster162/continuityos/blob/master/THREAT_MODEL.md ===
echo.
pause
