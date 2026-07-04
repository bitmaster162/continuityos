@echo off
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set CONTINUITYOS_SILENCE_EMBED_WARN=1
set OUT=sim_verify_out.txt
echo === py_compile === > "%OUT%"
python -m py_compile continuityos\sim\contracts.py continuityos\sim\gateway.py continuityos\sim\memory_plane.py continuityos\sim\detector.py continuityos\sim\rollback.py continuityos\sim\loop.py tests\test_sim.py >> "%OUT%" 2>&1 && echo COMPILE_ALL_OK >> "%OUT%"
echo === memory_plane self-test === >> "%OUT%"
python -m continuityos.sim.memory_plane >> "%OUT%" 2>&1
echo === rollback self-test === >> "%OUT%"
python -m continuityos.sim.rollback >> "%OUT%" 2>&1
echo === loop (mock, verify phase) === >> "%OUT%"
python -m continuityos.sim.loop --objective verify --iters 10 --mock >> "%OUT%" 2>&1
echo === manual test_sim key invariants === >> "%OUT%"
python -c "import tests.test_sim as t; t.test_spec_id_covers_all_material_fields(); t.test_different_candidates_do_not_co_confirm(); t.test_same_run_id_does_not_double_count(); t.test_rollback_failure_is_flagged(); t.test_gateway_denies_canon_breach(); t.test_gateway_holds_on_no_budget(); t.test_verification_phase_reaches_canon_in_loop(); print('ALL_TEST_SIM_INVARIANTS_PASS')" >> "%OUT%" 2>&1
echo === DONE === >> "%OUT%"
exit
