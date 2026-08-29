#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SOURCE_SCHEMA "sovereign-twin.windows-runtime-source/v3"

static char *read_all_utf8(const wchar_t *path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 2 || sz.QuadPart > 1024 * 1024) {
        CloseHandle(h); return NULL;
    }
    char *buf = (char *)malloc((size_t)sz.QuadPart + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL);
    CloseHandle(h);
    if (!ok || got != (DWORD)sz.QuadPart) { free(buf); return NULL; }
    buf[got] = '\0';
    return buf;
}

static const char *find_value(const char *json, const char *key) {
    size_t key_len = strlen(key);
    const char *p = json;
    while ((p = strchr(p, '"')) != NULL) {
        ++p;
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '"') {
            p += key_len + 1;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
            if (*p++ != ':') continue;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
            return p;
        }
        ++p;
    }
    return NULL;
}

static char *json_string(const char *json, const char *key) {
    const char *p = find_value(json, key);
    if (!p || *p++ != '"') return NULL;
    size_t cap = 128, len = 0;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    while (*p && *p != '"') {
        unsigned char ch = (unsigned char)*p++;
        if (ch == '\\') {
            ch = (unsigned char)*p++;
            switch (ch) {
                case '"': case '\\': case '/': break;
                case 'b': ch = '\b'; break;
                case 'f': ch = '\f'; break;
                case 'n': ch = '\n'; break;
                case 'r': ch = '\r'; break;
                case 't': ch = '\t'; break;
                default: free(out); return NULL; /* reject \u and unknown escapes fail-closed */
            }
        }
        if (len + 2 > cap) {
            cap *= 2;
            char *grown = (char *)realloc(out, cap);
            if (!grown) { free(out); return NULL; }
            out = grown;
        }
        out[len++] = (char)ch;
    }
    if (*p != '"') { free(out); return NULL; }
    out[len] = '\0';
    return out;
}

static int json_bool_false(const char *json, const char *key) {
    const char *p = find_value(json, key);
    return p && strncmp(p, "false", 5) == 0;
}

static wchar_t *utf8_to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *out = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!out) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, n)) {
        free(out); return NULL;
    }
    return out;
}

static int append_text(wchar_t **buf, size_t *cap, size_t *len, const wchar_t *text) {
    size_t need = wcslen(text);
    if (*len + need + 1 > *cap) {
        size_t next = *cap ? *cap : 256;
        while (next < *len + need + 1) next *= 2;
        wchar_t *grown = (wchar_t *)realloc(*buf, next * sizeof(wchar_t));
        if (!grown) return 0;
        *buf = grown; *cap = next;
    }
    memcpy(*buf + *len, text, need * sizeof(wchar_t));
    *len += need; (*buf)[*len] = L'\0';
    return 1;
}

static int append_quoted_arg(wchar_t **buf, size_t *cap, size_t *len, const wchar_t *arg) {
    int quote = (*arg == L'\0' || wcspbrk(arg, L" \t\n\v\"") != NULL);
    if (!quote) return append_text(buf, cap, len, arg);
    if (!append_text(buf, cap, len, L"\"")) return 0;
    size_t slashes = 0;
    for (const wchar_t *p = arg;; ++p) {
        wchar_t ch = *p;
        if (ch == L'\\') { ++slashes; continue; }
        if (ch == L'\"') {
            for (size_t i = 0; i < slashes * 2 + 1; ++i) if (!append_text(buf, cap, len, L"\\")) return 0;
            if (!append_text(buf, cap, len, L"\"")) return 0;
            slashes = 0; continue;
        }
        if (ch == L'\0') {
            for (size_t i = 0; i < slashes * 2; ++i) if (!append_text(buf, cap, len, L"\\")) return 0;
            break;
        }
        for (size_t i = 0; i < slashes; ++i) if (!append_text(buf, cap, len, L"\\")) return 0;
        slashes = 0;
        wchar_t tmp[2] = {ch, L'\0'};
        if (!append_text(buf, cap, len, tmp)) return 0;
    }
    return append_text(buf, cap, len, L"\"");
}

static int spawn(const wchar_t *exe, wchar_t **args, int argc, const wchar_t *cwd) {
    wchar_t *cmd = NULL; size_t cap = 0, len = 0;
    if (!append_quoted_arg(&cmd, &cap, &len, exe)) return 131;
    for (int i = 0; i < argc; ++i) {
        if (!append_text(&cmd, &cap, &len, L" ") || !append_quoted_arg(&cmd, &cap, &len, args[i])) {
            free(cmd); return 131;
        }
    }
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi)); si.cb = sizeof(si);
    BOOL ok = CreateProcessW(exe, cmd, NULL, NULL, TRUE, 0, NULL, cwd, &si, &pi);
    free(cmd);
    if (!ok) return 132;
    CloseHandle(pi.hThread); WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 133; if (!GetExitCodeProcess(pi.hProcess, &code)) code = 133;
    CloseHandle(pi.hProcess); return (int)code;
}

static int parent_directory(wchar_t *path) {
    wchar_t *slash = wcsrchr(path, L'\\');
    if (!slash) return 0;
    *slash = L'\0'; return 1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || (wcscmp(argv[1], L"--serve") && wcscmp(argv[1], L"--open") && wcscmp(argv[1], L"--status")))
        return 120;

    wchar_t self[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(NULL, self, (DWORD)(sizeof(self) / sizeof(self[0])));
    if (n == 0 || n >= sizeof(self) / sizeof(self[0])) return 121;
    if (!parent_directory(self)) return 122;

    wchar_t manifest[MAX_PATH * 4];
    if (swprintf_s(manifest, sizeof(manifest)/sizeof(manifest[0]), L"%ls\\runtime-source.json", self) < 0) return 123;
    char *json = read_all_utf8(manifest);
    if (!json) return 124;

    char *schema = json_string(json, "schema");
    char *authority = json_string(json, "execution_authority");
    char *twin8 = json_string(json, "twin_executable");
    char *db8 = json_string(json, "memory_db");
    char *queue8 = json_string(json, "admission_queue");
    char *embed8 = json_string(json, "embedding_model");
    int safe = schema && authority && twin8 && db8 && queue8 && embed8 &&
               strcmp(schema, SOURCE_SCHEMA) == 0 && strcmp(authority, "NONE") == 0 &&
               json_bool_false(json, "can_execute");
    free(schema); free(authority); free(json);
    if (!safe) { free(twin8); free(db8); free(queue8); free(embed8); return 125; }

    wchar_t *twin = utf8_to_wide(twin8), *db = utf8_to_wide(db8), *queue = utf8_to_wide(queue8), *embed = utf8_to_wide(embed8);
    free(twin8); free(db8); free(queue8); free(embed8);
    if (!twin || !db || !queue || !embed) { free(twin); free(db); free(queue); free(embed); return 126; }
    if (GetFileAttributesW(twin) == INVALID_FILE_ATTRIBUTES || GetFileAttributesW(db) == INVALID_FILE_ATTRIBUTES) {
        free(twin); free(db); free(queue); free(embed); return 127;
    }

    if (wcscmp(argv[1], L"--open") == 0) {
        HINSTANCE r = ShellExecuteW(NULL, L"open", L"http://127.0.0.1:8765", NULL, NULL, SW_SHOWNORMAL);
        free(twin); free(db); free(queue); free(embed);
        return ((INT_PTR)r > 32) ? 0 : 128;
    }

    wchar_t *args[11]; int ac = 0;
    args[ac++] = L"--db"; args[ac++] = db;
    args[ac++] = L"--admission-queue"; args[ac++] = queue;
    args[ac++] = L"--embedding-model"; args[ac++] = embed;
    if (wcscmp(argv[1], L"--serve") == 0) {
        args[ac++] = L"serve"; args[ac++] = L"--host"; args[ac++] = L"127.0.0.1"; args[ac++] = L"--port"; args[ac++] = L"8765";
    } else {
        args[ac++] = L"memory-doctor";
    }

    wchar_t cwd[MAX_PATH * 4]; wcscpy_s(cwd, sizeof(cwd)/sizeof(cwd[0]), twin);
    if (!parent_directory(cwd) || !parent_directory(cwd)) { free(twin); free(db); free(queue); free(embed); return 129; }
    int rc = spawn(twin, args, ac, cwd);
    free(twin); free(db); free(queue); free(embed);
    return rc;
}
