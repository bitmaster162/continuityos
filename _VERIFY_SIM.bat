@echo off
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set CONTINUITYOS_SILENCE_EMBED_WARN=1
set OUT=sim_verify_out.txt
echo === py_compile === > "%OUT%"
python -m py_compile continuityos\sim\memory_plane.py continuityos\sim\loop.py continuityos\sim\rollback.py tests\test_sim.py >> "%OUT%" 2>&1 && echo COMPILE_OK >> "%OUT%"
echo === all test_sim invariants (manual) === >> "%OUT%"
python -c "import tests.test_sim as t; [getattr(t,n)() for n in dir(t) if n.startswith('test_')]; print('ALL_TEST_SIM_PASS ('+str(len([n for n in dir(t) if n.startswith('test_')]))+' tests)')" >> "%OUT%" 2>&1
echo === DONE === >> "%OUT%"
exit
