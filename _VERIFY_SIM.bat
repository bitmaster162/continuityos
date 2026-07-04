@echo off
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set CONTINUITYOS_SILENCE_EMBED_WARN=1
set OUT=sim_verify_out.txt
echo === py_compile === > "%OUT%"
python -m py_compile continuityos\sim\memory_plane.py continuityos\sim\loop.py continuityos\sim\rollback.py tests\test_sim.py >> "%OUT%" 2>&1 && echo COMPILE_OK >> "%OUT%"
echo === module self-tests === >> "%OUT%"
python -m continuityos.sim.memory_plane >> "%OUT%" 2>&1
python -m continuityos.sim.rollback >> "%OUT%" 2>&1
echo === test_sim (all, with monkeypatch shim) === >> "%OUT%"
python _verify_sim.py >> "%OUT%" 2>&1
echo === DONE === >> "%OUT%"
exit
