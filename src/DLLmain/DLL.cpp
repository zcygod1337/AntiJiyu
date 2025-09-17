#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

#ifndef WDA_MONITOR
#define WDA_MONITOR 1
#endif

#include <windows.h>
#include <winuser.h>
#include <string.h>

struct Config {
    bool enableTopMost;
    bool enableAntiCapture;
} g_config = {true, true};

static HWND g_mainWnd = NULL;

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid == (DWORD)lParam && GetWindow(hWnd, GW_OWNER) == NULL && IsWindowVisible(hWnd))
    {
        g_mainWnd = hWnd;
        MessageBox(NULL,"注入完毕","zcygod",MB_OK);
        return FALSE; // 找到了主窗口, 结束遍历
    }
    return TRUE; // 继续遍历
}

HWND GetMainWindow(DWORD pid)
{
    EnumWindows(EnumWindowsProc, (LPARAM)pid);
    return g_mainWnd;
}

void ApplySettings()
{
    HWND hwnd = GetMainWindow(GetCurrentProcessId());
    if (!hwnd) return;

    // 顶置设置
    if (g_config.enableTopMost)
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    else
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    // 防截屏
    if (g_config.enableAntiCapture)
    {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (hUser32)
        {
            typedef BOOL (WINAPI *PFN_SetWindowDisplayAffinity)(HWND, DWORD);
            auto pSWDA = reinterpret_cast<PFN_SetWindowDisplayAffinity>(GetProcAddress(hUser32, "SetWindowDisplayAffinity"));
            if (pSWDA)
            {
                pSWDA(hwnd, WDA_EXCLUDEFROMCAPTURE);
            }
        }
    }
    else
    {
        HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
        if (hUser32)
        {
            typedef BOOL (WINAPI *PFN_SetWindowDisplayAffinity)(HWND, DWORD);
            auto pSWDA = reinterpret_cast<PFN_SetWindowDisplayAffinity>(GetProcAddress(hUser32, "SetWindowDisplayAffinity"));
            if (pSWDA)
            {
                pSWDA(hwnd, WDA_MONITOR);
            }
        }
    }
}

extern "C" __declspec(dllexport) DWORD __stdcall SetFlags(LPVOID lpParam)
{
    if (!lpParam) return 0;
    struct Flags { BOOL top; BOOL cap; };
    Flags f;
    memcpy(&f, lpParam, sizeof(f));
    g_config.enableTopMost = f.top != 0;
    g_config.enableAntiCapture = f.cap != 0;
    ApplySettings();
    return 1;
}

DWORD WINAPI WorkerThread(LPVOID lpParam)
{
    // 解析命令行参数
    LPWSTR cmdLine = GetCommandLineW();
    if (cmdLine) {
        if (wcsstr(cmdLine, L"-notopmost")) {
            g_config.enableTopMost = false;
        }
        if (wcsstr(cmdLine, L"-nocapture")) {
            g_config.enableAntiCapture = false;
        }
    }

    ApplySettings();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule); // 减少线程通知开销
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
    return TRUE;
} 
