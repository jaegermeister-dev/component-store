#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <shlobj.h>

/* Reapply Apple's per-user preferences through its original AppleMTP API.
 * No device installation, background polling, registry preference changes,
 * elevation, or global input interception. Retry only during startup.
 */
static HANDLE log_file = INVALID_HANDLE_VALUE;

static void record(const char *phase, DWORD a, DWORD b, DWORD c) {
    char line[320];
    SYSTEMTIME t;
    DWORD count;
    GetSystemTime(&t);
    int n = wsprintfA(line, "%04u-%02u-%02uT%02u:%02u:%02uZ %s a=%lu b=%lu c=%lu\r\n",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, phase, a, b, c);
    if (log_file != INVALID_HANDLE_VALUE && n > 0 && n < (int)sizeof(line))
        WriteFile(log_file, line, (DWORD)n, &count, NULL);
}

static DWORD preferences(DWORD *mode, DWORD *used_default) {
    HKEY key;
    DWORD type = 0, bytes = sizeof(*mode);
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Apple Inc.\\Trackpad", 0, KEY_QUERY_VALUE, &key);
    *used_default = 0;
    if (result == ERROR_FILE_NOT_FOUND) {
        *mode = 0x28; /* Default in the original Apple Boot Camp utility. */
        *used_default = 1;
        return ERROR_SUCCESS;
    }
    if (result != ERROR_SUCCESS) return (DWORD)result;
    result = RegQueryValueExW(key, L"Mode", NULL, &type, (BYTE *)mode, &bytes);
    RegCloseKey(key);
    if (result == ERROR_FILE_NOT_FOUND) {
        *mode = 0x28;
        *used_default = 1;
        return ERROR_SUCCESS;
    }
    if (result != ERROR_SUCCESS) return (DWORD)result;
    if (type != REG_DWORD || bytes != sizeof(*mode)) return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}

static DWORD apply(DWORD mode, DWORD *before, DWORD *after) {
    HANDLE device = CreateFileW(L"\\\\.\\AppleTrackpad", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) return GetLastError();
    DWORD count = 0, error = ERROR_SUCCESS;
    if (!DeviceIoControl(device, 0xF2000, NULL, 0, before, sizeof(*before), &count, NULL))
        error = GetLastError();
    else if (count != sizeof(*before)) error = ERROR_INVALID_DATA;
    if (!error && *before != mode &&
        !DeviceIoControl(device, 0xF2004, &mode, sizeof(mode), NULL, 0, &count, NULL))
        error = GetLastError();
    if (!error) {
        if (!DeviceIoControl(device, 0xF2000, NULL, 0, after, sizeof(*after), &count, NULL))
            error = GetLastError();
        else if (count != sizeof(*after) || *after != mode) error = ERROR_INVALID_DATA;
    }
    CloseHandle(device);
    return error;
}

void Windows7Entry(void) {
    DWORD session = 0, exit_code = 1;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session == 0) ExitProcess(2);
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\BackToSeven-AppleTrackpad-Preferences-v1");
    if (!mutex) ExitProcess(3);
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(mutex); ExitProcess(0); }

    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)) &&
        lstrlenW(path) < MAX_PATH - 48) {
        lstrcatW(path, L"\\BackToSeven");
        if (CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
            lstrcatW(path, L"\\Trackpad-Preferences.log");
            log_file = CreateFileW(path, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
    }
    DWORD elevated = 0xFFFFFFFF, size = sizeof(TOKEN_ELEVATION);
    TOKEN_ELEVATION token_info;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &token_info, size, &size))
            elevated = token_info.TokenIsElevated;
        CloseHandle(token);
    }
    record("BEGIN session/elevated/version", session, elevated, 1);
    DWORD error = 0, before = 0, after = 0, mode = 0, used_default = 0;
    for (DWORD attempt = 0; attempt < 60; ++attempt) {
        error = preferences(&mode, &used_default);
        if (error) break;
        error = apply(mode, &before, &after);
        if (!error) {
            record("PASS before/after/default", before, after, used_default);
            exit_code = 0;
            break;
        }
        if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_DATA) break;
        if (attempt < 59) Sleep(1000);
    }
    if (exit_code) record("FAIL error/desired/default", error, mode, used_default);
    if (log_file != INVALID_HANDLE_VALUE) CloseHandle(log_file);
    CloseHandle(mutex);
    ExitProcess(exit_code);
}
