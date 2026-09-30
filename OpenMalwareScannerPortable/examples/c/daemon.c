/* Daemon mode (Windows): poll a directory, scan new/changed files, print hits.
   Build: cl daemon.c /link openedr_static.lib
   Run: daemon.exe [watchDir]
   NOTE: no SHA-256 in stock C; unchanged files are skipped by (size, mtime). */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "openedr_static.h"

#define POLL_MS 2000
#define MAX_FILES 65536
#define MAX_SIZE_BYTES (48LL * 1024 * 1024)

typedef struct {
    wchar_t path[MAX_PATH];
    long long size;
    long long mtime;
} SeenEntry;

static SeenEntry g_seen[MAX_FILES];
static int g_seenCount = 0;
static long long g_scanned = 0;
static long long g_hits = 0;

static int IsFlagged(const char* verdict) {
    return strcmp(verdict, "Malicious") == 0 || strcmp(verdict, "Suspicious") == 0;
}

/* Minimal "\"verdict\": \"X\"" extractor. Returns static buffer. */
static const char* ExtractVerdict(const char* json) {
    static char verdict[32];
    const char* i = strstr(json, "\"verdict\"");
    const char* c;
    const char* q1;
    const char* q2;
    size_t n;
    if (!i) return "Unknown";
    c = strchr(i, ':');
    if (!c) return "Unknown";
    q1 = strchr(c, '"');
    if (!q1) return "Unknown";
    q2 = strchr(q1 + 1, '"');
    if (!q2) return "Unknown";
    n = (size_t)(q2 - (q1 + 1));
    if (n >= sizeof(verdict)) n = sizeof(verdict) - 1;
    memcpy(verdict, q1 + 1, n);
    verdict[n] = '\0';
    return verdict;
}

static long long FileTimeNs(FILETIME ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (long long)(u.QuadPart * 100);
}

static int SeenFresh(const wchar_t* path, long long size, long long mtime) {
    int i;
    for (i = 0; i < g_seenCount; ++i) {
        if (wcscmp(g_seen[i].path, path) == 0) {
            if (g_seen[i].size == size && g_seen[i].mtime == mtime)
                return 0;
            g_seen[i].size = size;
            g_seen[i].mtime = mtime;
            return 1;
        }
    }
    if (g_seenCount < MAX_FILES) {
        wcscpy_s(g_seen[g_seenCount].path, MAX_PATH, path);
        g_seen[g_seenCount].size = size;
        g_seen[g_seenCount].mtime = mtime;
        ++g_seenCount;
    }
    return 1;
}

static void ScanOne(const wchar_t* wpath) {
    char upath[MAX_PATH * 4];
    char* json;
    const char* verdict;
    int n = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, upath, (int)sizeof(upath), NULL, NULL);
    if (n <= 1) return;
    json = openedr_static_scan_file(upath);
    if (json == NULL) {
        fprintf(stderr, "[-] scan failed %s\n", upath);
        return;
    }
    verdict = ExtractVerdict(json);
    ++g_scanned;
    if (IsFlagged(verdict)) {
        ++g_hits;
        printf("[!] %s :: %s\n", verdict, upath);
        fflush(stdout);
    }
    openedr_static_free_string(json);
}

static void Sweep(const wchar_t* wdir) {
    wchar_t pattern[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*", wdir);
    h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        wchar_t full[MAX_PATH];
        long long size;
        long long mtime;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        _snwprintf_s(full, MAX_PATH, _TRUNCATE, L"%s\\%s", wdir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            Sweep(full);
            continue;
        }
        size = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        mtime = FileTimeNs(fd.ftLastWriteTime);
        if (size <= 0 || size > MAX_SIZE_BYTES) continue;
        if (SeenFresh(full, size, mtime))
            ScanOne(full);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

int main(int argc, char* argv[]) {
    wchar_t wdir[MAX_PATH];
    wchar_t* warg = NULL;
    size_t arglen;
    if (openedr_static_init("OpenMalwareScannerPortable") != 0) {
        fprintf(stderr, "[-] Failed to initialize OpenEDR static scanner!\n");
        return 1;
    }
    if (argc > 1) {
        arglen = strlen(argv[1]) + 1;
        warg = (wchar_t*)malloc(arglen * sizeof(wchar_t));
        if (warg) {
            MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, warg, (int)arglen);
            wcsncpy_s(wdir, MAX_PATH, warg, _TRUNCATE);
            free(warg);
        } else {
            wcsncpy_s(wdir, MAX_PATH, L".", _TRUNCATE);
        }
    } else {
        wcsncpy_s(wdir, MAX_PATH, L".", _TRUNCATE);
    }
    printf("[*] Watching %ls - Ctrl+C to stop\n", wdir);
    for (;;) {
        Sweep(wdir);
        printf("[...] scanned=%lld hits=%lld\n", g_scanned, g_hits);
        fflush(stdout);
        Sleep(POLL_MS);
    }
    return 0;
}
