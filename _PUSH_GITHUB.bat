@echo off
REM ============================================================
REM  Push ContinuityOS 0.8.8 (adds Sim-OS closed-loop bridge)
REM  to GitHub so the repo shows both ContinuityOS and Sim-OS.
REM ============================================================
cd /d "%~dp0"
echo.
echo === Staging all changes ===
git add -A
echo.
echo === Commit ===
git commit -m "v0.8.8: Sim-OS closed-loop simulation bridge (continuityos/sim) + cos sim command"
echo.
echo === Tag ===
git tag v0.8.8 2>nul
echo.
echo === Push (code + tags) ===
git push origin master --tags
echo.
echo === Done. Check: https://github.com/bitmaster162/continuityos ===
echo   (continuityos/sim/ now visible alongside the memory core)
echo.
pause
