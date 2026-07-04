@echo off
cd /d "%~dp0"
git add -A
git commit -m "test_sim: strengthen durable proofs — true A->B->rollback(A)->restart durability + rehydrate query-failure fail-closed (not just store-open); fix stale confirmations comment (GPT 3rd audit test gaps)"
git push origin master
echo Done
pause
