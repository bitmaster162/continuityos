@echo off
cd /d "%~dp0"
git add -A
git commit -m "test_sim: add durable rehydrate + rollback-survives-restart + broken-store-fails-closed regressions (PR-9 test matrix complete, GPT audit)"
git push origin master
echo Done
pause
