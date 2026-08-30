#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define SOURCE_SCHEMA "sovereign-twin.windows-runtime-source/v3"
#define EXPECTED_FIELDS 18

typedef struct {
    char *schema;
    char *repository;
    char *source_sha;
    char *installed_at_utc;
    char *python;
    char *twin_executable;
    char *memory_db;
    char *admission_queue;
    char *llm_server;
    char *ui;
    char *fast_model;
    char *deep_model;
    char *embedding_model;
    char *execution_authority;
    char *memory_activated_at_utc;
    char *memory_manifest;
    int can_execute;
    int can_execute_seen;
    int memory_embedding_dimension;
    int memory_embedding_dimension_seen;
    uint64_t seen_mask;
} RuntimePointer;

enum {
    F_SCHEMA = 0,
    F_REPOSITORY,
    F_SOURCE_SHA,
    F_INSTALLED_AT,
    F_PYTHON,
    F_TWIN,
    F_MEMORY_DB,
    F_QUEUE,
    F_LLM,
    F_UI,
    F_FAST,
    F_DEEP,
    F_EMBED,
    F_AUTHORITY,
    F_CAN_EXECUTE,
    F_MEMORY_ACTIVATED,
    F_MEMORY_MANIFEST,
    F_MEMORY_DIMENSION
};

static void free_pointer(RuntimePointer *p) {
    free(p->schema);
    free(p->repository);
    free(p->source_sha);
    free(p->installed_at_utc);
    free(p->python);
    free(p->twin_executable);
    free(p->memory_db);
    free(p->admission_queue);
    free(p->llm_server);
    free(p->ui);
    free(p->fast_model);
    free(p->deep_model);
    free(p->embedding_model);
    free(p->execution_authority);
    free(p->memory_activated_at_utc);
    free(p->memory_manifest);
    ZeroMemory(p, sizeof(*p));
}

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

static void skip_ws(const char **pp) {
    const unsigned char *p = (const unsigned char *)*pp;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    *pp = (const char *)p;
}

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
    return -1;
}

static int parse_hex4(const char **pp, uint32_t *out) {
    uint32_t value = 0;
    const unsigned char *p = (const unsigned char *)*pp;
    for (int i = 0; i < 4; ++i) {
        unsigned char c = *p++;
        if (c == 0) return 0;
        int v = hex_value(c);
        if (v < 0) return 0;
        value = (value << 4) | (uint32_t)v;
    }
    *pp = (const char *)p;
    *out = value;
    return 1;
}

static int append_byte(char **buf, size_t *cap, size_t *len, unsigned char ch) {
    if (*len + 2 > *cap) {
        size_t next = *cap ? *cap : 128;
        while (next < *len + 2) next *= 2;
        char *grown = (char *)realloc(*buf, next);
        if (!grown) return 0;
        *buf = grown;
        *cap = next;
    }
    (*buf)[(*len)++] = (char)ch;
    (*buf)[*len] = '\0';
    return 1;
}

static int append_codepoint_utf8(char **buf, size_t *cap, size_t *len, uint32_t cp) {
    if (cp <= 0x7F) return append_byte(buf, cap, len, (unsigned char)cp);
    if (cp <= 0x7FF) {
        return append_byte(buf, cap, len, (unsigned char)(0xC0 | (cp >> 6))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | (cp & 0x3F)));
    }
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    if (cp <= 0xFFFF) {
        return append_byte(buf, cap, len, (unsigned char)(0xE0 | (cp >> 12))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | ((cp >> 6) & 0x3F))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | (cp & 0x3F)));
    }
    if (cp <= 0x10FFFF) {
        return append_byte(buf, cap, len, (unsigned char)(0xF0 | (cp >> 18))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | ((cp >> 12) & 0x3F))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | ((cp >> 6) & 0x3F))) &&
               append_byte(buf, cap, len, (unsigned char)(0x80 | (cp & 0x3F)));
    }
    return 0;
}

/* Strict JSON string parser with UTF-16 surrogate support for \u escapes. */
static char *parse_json_string(const char **pp) {
    const unsigned char *p = (const unsigned char *)*pp;
    if (*p++ != '"') return NULL;
    char *out = NULL;
    size_t cap = 0, len = 0;
    if (!append_byte(&out, &cap, &len, 0)) return NULL;
    len = 0;

    for (;;) {
        unsigned char ch = *p++;
        if (ch == 0) { free(out); return NULL; }
        if (ch == '"') break;
        if (ch < 0x20) { free(out); return NULL; }
        if (ch != '\\') {
            if (!append_byte(&out, &cap, &len, ch)) { free(out); return NULL; }
            continue;
        }

        unsigned char esc = *p++;
        switch (esc) {
            case '"': case '\\': case '/':
                if (!append_byte(&out, &cap, &len, esc)) { free(out); return NULL; }
                break;
            case 'b':
                if (!append_byte(&out, &cap, &len, '\b')) { free(out); return NULL; }
                break;
            case 'f':
                if (!append_byte(&out, &cap, &len, '\f')) { free(out); return NULL; }
                break;
            case 'n':
                if (!append_byte(&out, &cap, &len, '\n')) { free(out); return NULL; }
                break;
            case 'r':
                if (!append_byte(&out, &cap, &len, '\r')) { free(out); return NULL; }
                break;
            case 't':
                if (!append_byte(&out, &cap, &len, '\t')) { free(out); return NULL; }
                break;
            case 'u': {
                const char *q = (const char *)p;
                uint32_t cp = 0;
                if (!parse_hex4(&q, &cp)) { free(out); return NULL; }
                p = (const unsigned char *)q;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (p[0] != '\\' || p[1] != 'u') { free(out); return NULL; }
                    q = (const char *)(p + 2);
                    uint32_t low = 0;
                    if (!parse_hex4(&q, &low) || low < 0xDC00 || low > 0xDFFF) {
                        free(out); return NULL;
                    }
                    p = (const unsigned char *)q;
                    cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    free(out); return NULL;
                }
                if (!append_codepoint_utf8(&out, &cap, &len, cp)) { free(out); return NULL; }
                break;
            }
            default:
                free(out); return NULL;
        }
    }

    *pp = (const char *)p;
    return out;
}

static int parse_exact_false(const char **pp, int *value) {
    const char *p = *pp;
    if (strncmp(p, "false", 5) != 0) return 0;
    p += 5;
    if (*p && *p != ',' && *p != '}' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return 0;
    *value = 0;
    *pp = p;
    return 1;
}

static int parse_positive_int(const char **pp, int *value) {
    const char *p = *pp;
    if (*p < '1' || *p > '9') return 0;
    unsigned long v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (unsigned long)(*p - '0');
        if (v > 2147483647UL) return 0;
        ++p;
    }
    if (*p && *p != ',' && *p != '}' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return 0;
    *value = (int)v;
    *pp = p;
    return 1;
}

static int field_id(const char *key) {
    static const char *names[EXPECTED_FIELDS] = {
        "schema", "repository", "source_sha", "installed_at_utc", "python",
        "twin_executable", "memory_db", "admission_queue", "llm_server", "ui",
        "fast_model", "deep_model", "embedding_model", "execution_authority",
        "can_execute", "memory_activated_at_utc", "memory_manifest",
        "memory_embedding_dimension"
    };
    for (int i = 0; i < EXPECTED_FIELDS; ++i) {
        if (strcmp(key, names[i]) == 0) return i;
    }
    return -1;
}

static char **string_slot(RuntimePointer *p, int id) {
    switch (id) {
        case F_SCHEMA: return &p->schema;
        case F_REPOSITORY: return &p->repository;
        case F_SOURCE_SHA: return &p->source_sha;
        case F_INSTALLED_AT: return &p->installed_at_utc;
        case F_PYTHON: return &p->python;
        case F_TWIN: return &p->twin_executable;
        case F_MEMORY_DB: return &p->memory_db;
        case F_QUEUE: return &p->admission_queue;
        case F_LLM: return &p->llm_server;
        case F_UI: return &p->ui;
        case F_FAST: return &p->fast_model;
        case F_DEEP: return &p->deep_model;
        case F_EMBED: return &p->embedding_model;
        case F_AUTHORITY: return &p->execution_authority;
        case F_MEMORY_ACTIVATED: return &p->memory_activated_at_utc;
        case F_MEMORY_MANIFEST: return &p->memory_manifest;
        default: return NULL;
    }
}

static int parse_pointer_json(const char *json, RuntimePointer *out) {
    ZeroMemory(out, sizeof(*out));
    const char *p = json;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;
    skip_ws(&p);
    if (*p++ != '{') return 0;
    skip_ws(&p);

    if (*p == '}') return 0;
    for (;;) {
        char *key = parse_json_string(&p);
        if (!key) goto fail;
        int id = field_id(key);
        free(key);
        if (id < 0) goto fail;
        uint64_t bit = UINT64_C(1) << id;
        if (out->seen_mask & bit) goto fail;
        out->seen_mask |= bit;

        skip_ws(&p);
        if (*p++ != ':') goto fail;
        skip_ws(&p);

        if (id == F_CAN_EXECUTE) {
            if (!parse_exact_false(&p, &out->can_execute)) goto fail;
            out->can_execute_seen = 1;
        } else if (id == F_MEMORY_DIMENSION) {
            if (!parse_positive_int(&p, &out->memory_embedding_dimension)) goto fail;
            out->memory_embedding_dimension_seen = 1;
        } else {
            char **slot = string_slot(out, id);
            if (!slot) goto fail;
            *slot = parse_json_string(&p);
            if (!*slot || !**slot) goto fail;
        }

        skip_ws(&p);
        if (*p == ',') {
            ++p;
            skip_ws(&p);
            continue;
        }
        if (*p == '}') {
            ++p;
            break;
        }
        goto fail;
    }

    skip_ws(&p);
    if (*p != '\0') goto fail;
    if (out->seen_mask != ((UINT64_C(1) << EXPECTED_FIELDS) - 1)) goto fail;
    return 1;

fail:
    free_pointer(out);
    return 0;
}

static int is_hex_sha40(const char *s) {
    if (!s || strlen(s) != 40) return 0;
    for (int i = 0; i < 40; ++i) if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
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

static int normalize_full_path(const wchar_t *src, wchar_t *dst, DWORD cap) {
    DWORD n = GetFullPathNameW(src, cap, dst, NULL);
    return n > 0 && n < cap;
}

static int is_file_path(const wchar_t *path) {
    DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static const wchar_t *base_name(const wchar_t *path) {
    const wchar_t *p = wcsrchr(path, L'\\');
    return p ? p + 1 : path;
}

static int parse_loopback_url(const char *url, int *port_out) {
    const char *p = NULL;
    if (strncmp(url, "http://", 7) == 0) p = url + 7;
    else if (strncmp(url, "https://", 8) == 0) p = url + 8;
    else return 0;

    if (strncmp(p, "127.0.0.1:", 10) == 0) p += 10;
    else if (strncmp(p, "localhost:", 10) == 0) p += 10;
    else return 0;

    if (*p < '0' || *p > '9') return 0;
    unsigned long port = 0;
    while (*p >= '0' && *p <= '9') {
        port = port * 10 + (unsigned long)(*p - '0');
        if (port > 65535UL) return 0;
        ++p;
    }
    if (port == 0) return 0;
    if (*p == '/') ++p;
    if (*p != '\0') return 0;
    *port_out = (int)port;
    return 1;
}

static wchar_t *port_to_wide(int port) {
    wchar_t *out = (wchar_t *)malloc(16 * sizeof(wchar_t));
    if (!out) return NULL;
    if (swprintf_s(out, 16, L"%d", port) < 0) { free(out); return NULL; }
    return out;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || (wcscmp(argv[1], L"--serve") && wcscmp(argv[1], L"--open") && wcscmp(argv[1], L"--status") && wcscmp(argv[1], L"--control-center")))
        return 120;

    wchar_t product_root[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(NULL, product_root, (DWORD)(sizeof(product_root) / sizeof(product_root[0])));
    if (n == 0 || n >= sizeof(product_root) / sizeof(product_root[0])) return 121;
    if (!parent_directory(product_root)) return 122;

    wchar_t manifest[MAX_PATH * 4];
    if (swprintf_s(manifest, sizeof(manifest)/sizeof(manifest[0]), L"%ls\\runtime-source.json", product_root) < 0) return 123;
    char *json = read_all_utf8(manifest);
    if (!json) return 124;

    RuntimePointer rp;
    int parsed = parse_pointer_json(json, &rp);
    free(json);
    if (!parsed) return 125;

    int llm_port = 0, ui_port = 0;
    if (strcmp(rp.schema, SOURCE_SCHEMA) != 0 ||
        strcmp(rp.execution_authority, "NONE") != 0 ||
        !rp.can_execute_seen || rp.can_execute != 0 ||
        !rp.memory_embedding_dimension_seen || rp.memory_embedding_dimension <= 0 ||
        !is_hex_sha40(rp.source_sha) ||
        !parse_loopback_url(rp.llm_server, &llm_port) ||
        !parse_loopback_url(rp.ui, &ui_port)) {
        free_pointer(&rp); return 125;
    }

    wchar_t *python = utf8_to_wide(rp.python);
    wchar_t *twin = utf8_to_wide(rp.twin_executable);
    wchar_t *db = utf8_to_wide(rp.memory_db);
    wchar_t *queue = utf8_to_wide(rp.admission_queue);
    wchar_t *llm = utf8_to_wide(rp.llm_server);
    wchar_t *ui = utf8_to_wide(rp.ui);
    wchar_t *fast = utf8_to_wide(rp.fast_model);
    wchar_t *deep = utf8_to_wide(rp.deep_model);
    wchar_t *embed = utf8_to_wide(rp.embedding_model);
    wchar_t *memory_manifest = utf8_to_wide(rp.memory_manifest);
    if (!python || !twin || !db || !queue || !llm || !ui || !fast || !deep || !embed || !memory_manifest) {
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return 126;
    }

    wchar_t python_full[MAX_PATH * 4], twin_full[MAX_PATH * 4], db_full[MAX_PATH * 4], manifest_full[MAX_PATH * 4];
    if (!normalize_full_path(python, python_full, (DWORD)(sizeof(python_full)/sizeof(python_full[0]))) ||
        !normalize_full_path(twin, twin_full, (DWORD)(sizeof(twin_full)/sizeof(twin_full[0]))) ||
        !normalize_full_path(db, db_full, (DWORD)(sizeof(db_full)/sizeof(db_full[0]))) ||
        !normalize_full_path(memory_manifest, manifest_full, (DWORD)(sizeof(manifest_full)/sizeof(manifest_full[0]))) ||
        !is_file_path(python_full) || !is_file_path(twin_full) || !is_file_path(db_full) || !is_file_path(manifest_full) ||
        _wcsicmp(base_name(python_full), L"python.exe") != 0 ||
        _wcsicmp(base_name(twin_full), L"sovereign-twin.exe") != 0) {
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return 127;
    }

    wchar_t python_root[MAX_PATH * 4], twin_root[MAX_PATH * 4];
    wcscpy_s(python_root, sizeof(python_root)/sizeof(python_root[0]), python_full);
    wcscpy_s(twin_root, sizeof(twin_root)/sizeof(twin_root[0]), twin_full);
    if (!parent_directory(python_root) || !parent_directory(twin_root) || !parent_directory(twin_root) ||
        _wcsicmp(python_root, twin_root) != 0) {
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return 127;
    }

    if (wcscmp(argv[1], L"--open") == 0) {
        HINSTANCE r = ShellExecuteW(NULL, L"open", ui, NULL, NULL, SW_SHOWNORMAL);
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return ((INT_PTR)r > 32) ? 0 : 128;
    }

    if (!SetEnvironmentVariableW(L"SOVEREIGN_TWIN_FAST_MODEL", fast) ||
        !SetEnvironmentVariableW(L"SOVEREIGN_TWIN_DEEP_MODEL", deep)) {
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return 130;
    }

    if (wcscmp(argv[1], L"--control-center") == 0) {
        wchar_t *ccargs[16]; int ccac = 0;
        ccargs[ccac++] = L"-B";
        ccargs[ccac++] = L"-I";
        ccargs[ccac++] = L"-m";
        ccargs[ccac++] = L"continuityos.windows_control_center_entry";
        ccargs[ccac++] = L"--runtime-root"; ccargs[ccac++] = product_root;
        ccargs[ccac++] = L"--twin-url"; ccargs[ccac++] = ui;
        ccargs[ccac++] = L"--lm-studio-url"; ccargs[ccac++] = llm;
        int cc_rc = spawn(python_full, ccargs, ccac, python_root);
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return cc_rc;
    }

    wchar_t *port = port_to_wide(ui_port);
    if (!port) {
        free(python); free(twin); free(db); free(queue); free(llm); free(ui);
        free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
        return 130;
    }

    wchar_t *args[16]; int ac = 0;
    args[ac++] = L"--db"; args[ac++] = db_full;
    args[ac++] = L"--base-url"; args[ac++] = llm;
    args[ac++] = L"--admission-queue"; args[ac++] = queue;
    args[ac++] = L"--embedding-model"; args[ac++] = embed;
    if (wcscmp(argv[1], L"--serve") == 0) {
        args[ac++] = L"serve";
        args[ac++] = L"--host"; args[ac++] = L"127.0.0.1";
        args[ac++] = L"--port"; args[ac++] = port;
    } else {
        args[ac++] = L"memory-doctor";
    }

    int rc = spawn(twin_full, args, ac, twin_root);
    free(port);
    free(python); free(twin); free(db); free(queue); free(llm); free(ui);
    free(fast); free(deep); free(embed); free(memory_manifest); free_pointer(&rp);
    return rc;
}
