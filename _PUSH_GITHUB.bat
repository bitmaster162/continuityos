@echo off
cd /d "%~dp0"
git add -A
git commit -m "PR-9.2: budget RESERVATION before each run (affordability preflight, never crosses zero) + canon-row parse fails closed (corrupt sim_canon raises, not silently dropped); strict tests (budget_left>=0, corrupt-canon) — GPT 4th audit P0+P1"
git push origin master
echo Done
pause
