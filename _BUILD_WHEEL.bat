@echo off
REM ============================================================
REM  ContinuityOS 0.8.7 — build a shareable installer (.whl)
REM  Double-click this. It builds on YOUR machine (files are
REM  correct here) and drops the installer in the dist\ folder.
REM  Then send dist\continuityos-0.8.7-*.whl to your friend, or
REM  publish to PyPI (see the twine line at the bottom).
REM ============================================================
cd /d "%~dp0"
echo.
echo === [1/3] Making sure build tools are installed ===
python -m pip install --quiet --upgrade build
echo.
echo === [2/3] Building the installer (wheel + source) ===
rmdir /S /Q dist 2>nul
python -m build
echo.
echo === [3/3] Done ===
echo.
echo Your installer is here:
dir /b dist\*.whl
echo.
echo   HOW YOUR FRIEND INSTALLS IT:
echo   1) send them the .whl file from the dist\ folder
echo   2) they run:   pip install continuityos-0.8.7-py3-none-any.whl
echo   3) then:       cos setup
echo.
echo   TO PUBLISH TO PyPI INSTEAD (needs your PyPI token):
echo   python -m pip install --quiet twine ^&^& python -m twine upload dist\*
echo.
pause
