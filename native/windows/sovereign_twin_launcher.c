#define UNICODE
#define _UNICODE
#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

static int append_text(wchar_t **buf, size_t *cap, size_t *len, const wchar_t *text) {
    size_t need = wcslen(text);
    if (*len + need + 1 > *cap) {
        size_t next = *cap ? *cap : 256;
        while (next < *len + need + 1) next *= 2;
        wchar_t *grown = (wchar_t *)realloc(*buf, next * sizeof(wchar_t));
        if (!grown) return 0;
        *buf = grown;
        *cap = next;
    }
    memcpy(*buf + *len, text, need * sizeof(wchar_t));
    *len += need;
    (*buf)[*len] = L'\0';
    return 1;
}

/* Quote one argv element according to CommandLineToArgvW/CreateProcess rules. */
static int append_quoted_arg(wchar_t **buf, size_t *cap, size_t *len, const wchar_t *arg) {
    int quote = (*arg == L'\0' || wcspbrk(arg, L" \t\n\v\"") != NULL);
    if (!quote) return append_text(buf, cap, len, arg);
    if (!append_text(buf, cap, len, L"\"")) return 0;
    size_t slashes = 0;
    for (const wchar_t *p = arg;; ++p) {
        wchar_t ch = *p;
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        if (ch == L'\"') {
            for (size_t i = 0; i < slashes * 2 + 1; ++i)
                if (!append_text(buf, cap, len, L"\\")) return 0;
            if (!append_text(buf, cap, len, L"\"")) return 0;
            slashes = 0;
            continue;
        }
        if (ch == L'\0') {
            for (size_t i = 0; i < slashes * 2; ++i)
                if (!append_text(buf, cap, len, L"\\")) return 0;
            break;
        }
        for (size_t i = 0; i < slashes; ++i)
            if (!append_text(buf, cap, len, L"\\")) return 0;
        slashes = 0;
        wchar_t tmp[2] = {ch, L'\0'};
        if (!append_text(buf, cap, len, tmp)) return 0;
    }
    return append_text(buf, cap, len, L"\"");
}

static int parent_directory(wchar_t *path) {
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash) return 0;
    *slash = L'\0';
    return 1;
}

int wmain(int argc, wchar_t **argv) {
    wchar_t self[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(NULL, self, (DWORD)(sizeof(self) / sizeof(self[0])));
    if (n == 0 || n >= sizeof(self) / sizeof(self[0])) return 111;

    /* self = <runtime>\Scripts\sovereign-twin.exe -> runtime = parent(parent(self)) */
    wchar_t runtime[MAX_PATH * 4];
    wcscpy_s(runtime, sizeof(runtime) / sizeof(runtime[0]), self);
    if (!parent_directory(runtime) || !parent_directory(runtime)) return 112;

    wchar_t python[MAX_PATH * 4];
    if (swprintf_s(python, sizeof(python) / sizeof(python[0]), L"%ls\\python.exe", runtime) < 0)
        return 113;
    if (GetFileAttributesW(python) == INVALID_FILE_ATTRIBUTES) return 114;

    wchar_t *cmd = NULL;
    size_t cap = 0, len = 0;
    if (!append_quoted_arg(&cmd, &cap, &len, python)) return 115;
    if (!append_text(&cmd, &cap, &len, L" -I -m continuityos.sovereign_twin_cli")) {
        free(cmd); return 115;
    }
    for (int i = 1; i < argc; ++i) {
        if (!append_text(&cmd, &cap, &len, L" ") || !append_quoted_arg(&cmd, &cap, &len, argv[i])) {
            free(cmd); return 115;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    BOOL ok = CreateProcessW(
        python,
        cmd,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        runtime,
        &si,
        &pi
    );
    free(cmd);
    if (!ok) return 116;

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 117;
    if (!GetExitCodeProcess(pi.hProcess, &code)) code = 117;
    CloseHandle(pi.hProcess);
    return (int)code;
}
