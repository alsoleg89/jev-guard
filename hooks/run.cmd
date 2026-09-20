: << 'CMDBLOCK'
@echo off
rem jev-bouncer hook entry point, polyglot: cmd.exe runs this block, sh runs the one below.
rem Usage: run.cmd pre|post   (stdin and the exit code pass straight through)
rem Label lines are not echoed by cmd, so nothing pollutes the hook's stdout.
rem No goto and no parenthesised blocks: both are unreliable in LF-only .cmd files,
rem and this file must keep Unix line endings for the sh half to work.
set "JEVB=%~dp0..\bouncer.py"
set "JEVPY=python"
where python3.exe >nul 2>nul && set "JEVPY=python3"
where py.exe >nul 2>nul && set "JEVPY=py -3"
%JEVPY% "%JEVB%" %*
exit /b %ERRORLEVEL%
CMDBLOCK

# POSIX shell (and Git Bash on Windows) runs from here.
JEVB="$(dirname "$0")/../bouncer.py"
for JEVPY in python3 python py; do
    command -v "$JEVPY" >/dev/null 2>&1 && exec "$JEVPY" "$JEVB" "$@"
done
echo "jev-bouncer: no Python found (tried python3, python, py); hook skipped" >&2
exit 0
