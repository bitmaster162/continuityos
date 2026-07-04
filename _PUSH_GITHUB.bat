@echo off
REM ============================================================
REM  Push ContinuityOS 0.8.7 (with cos setup wizard) to GitHub
REM  so the repo matches the live PyPI release before Show HN.
REM ============================================================
cd /d "%~dp0"
echo.
echo === Staging all changes ===
git add -A
echo.
echo === Commit ===
git commit -m "v0.8.7: cos setup onboarding wizard + ORCA dashboard + sim_bridge scaffold"
echo.
echo === Tag ===
git tag v0.8.7 2>nul
echo.
echo === Push (code + tags) ===
git push origin master --tags
echo.
echo === Done. Check: https://github.com/bitmaster162/continuityos ===
echo.
pause
