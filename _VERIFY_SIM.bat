@echo off
cd /d "%~dp0"
set CONTINUITYOS_SILENCE_EMBED_WARN=1
set OUT=sim_verify_out.txt
echo === py_compile === > "%OUT%"
python -m py_compile continuityos\sim\contracts.py continuityos\sim\gateway.py continuityos\sim\memory_plane.py continuityos\sim\detector.py continuityos\sim\rollback.py continuityos\sim\loop.py >> "%OUT%" 2>&1 && echo COMPILE_ALL_OK >> "%OUT%"
echo === gateway === >> "%OUT%"
python -m continuityos.sim.gateway >> "%OUT%" 2>&1
echo === detector === >> "%OUT%"
python -m continuityos.sim.detector >> "%OUT%" 2>&1
echo === memory_plane === >> "%OUT%"
python -m continuityos.sim.memory_plane >> "%OUT%" 2>&1
echo === rollback === >> "%OUT%"
python -m continuityos.sim.rollback >> "%OUT%" 2>&1
echo === loop === >> "%OUT%"
python -m continuityos.sim.loop --objective verify --iters 5 >> "%OUT%" 2>&1
echo === DONE === >> "%OUT%"
exit
