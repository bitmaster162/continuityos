#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wchar.h>
#include <stdio.h>

static int print_env(const wchar_t *name, const wchar_t *label) {
    wchar_t value[1024];
    DWORD n = GetEnvironmentVariableW(name, value, (DWORD)(sizeof(value) / sizeof(value[0])));
    if (n == 0 || n >= sizeof(value) / sizeof(value[0])) return 2;
    if (wprintf(L"%ls=%ls\n", label, value) < 0) return 3;
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    int rc = print_env(L"SOVEREIGN_TWIN_FAST_MODEL", L"FAST");
    if (rc != 0) return rc;
    rc = print_env(L"SOVEREIGN_TWIN_DEEP_MODEL", L"DEEP");
    if (rc != 0) return rc;
    for (int i = 1; i < argc; ++i) {
        if (wprintf(L"ARG%d=%ls\n", i, argv[i]) < 0) return 3;
    }
    return 0;
}
