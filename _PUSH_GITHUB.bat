@echo off
cd /d "%~dp0"
git add -A
git commit -m "PR-9.1: close residual Sim-OS invariants (GPT 3rd audit) — VERIFY re-checks budget gate (P0-1), abandon clears candidate evidence (P0-2), replication keyed by candidate+seed not random uuid (P1-3), rehydrate fails closed on DB error (P1-4); strengthen tests (deterministic promotion, budget gate, reject reset, durable restart)"
git push origin master
echo Done
pause
