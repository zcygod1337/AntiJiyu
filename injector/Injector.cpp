#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

// 管理员权限清单
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")

// Toolkit_fix.reg 内容（嵌入）
static const char *kToolkitReg = R"REG(Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\B759697225BF14DA7F67596D9A687058C4EBAC60]
"Blob"=hex:04,00,00,00,01,00,00,00,10,00,00,00,0d,1d,2a,93,62,b0,c1,d9,55,78,\
  d7,20,09,b5,11,6b,0f,00,00,00,01,00,00,00,14,00,00,00,80,f4,32,d5,51,7d,e7,\
  1e,9b,51,4f,d7,44,e1,94,db,20,2d,5d,38,14,00,00,00,01,00,00,00,14,00,00,00,\
  d2,04,2a,6f,04,9f,40,9c,f5,3d,61,2c,53,d8,6b,03,a0,c7,d5,8a,19,00,00,00,01,\
  00,00,00,10,00,00,00,3c,9b,6e,bb,32,e5,fc,7d,3b,47,2c,9c,43,48,ba,43,03,00,\
  00,00,01,00,00,00,14,00,00,00,b7,59,69,72,25,bf,14,da,7f,67,59,6d,9a,68,70,\
  58,c4,eb,ac,60,5c,00,00,00,01,00,00,00,04,00,00,00,00,04,00,00,20,00,00,00,\
  01,00,00,00,3c,02,00,00,30,82,02,38,30,82,01,a5,a0,03,02,01,02,02,10,42,c5,\
  10,2e,2b,30,6b,98,4a,59,e8,f8,c8,25,f9,80,30,09,06,05,2b,0e,03,02,1d,05,00,\
  30,2c,31,1d,30,1b,06,03,55,04,03,13,14,42,65,6e,67,62,75,47,75,61,72,64,73,\
  20,52,6f,6f,74,20,43,41,31,0b,30,09,06,03,55,04,06,13,02,43,4e,30,20,17,0d,\
  32,31,31,32,33,31,31,36,30,30,30,30,5a,18,0f,32,30,39,39,31,32,33,31,31,36,\
  30,30,30,30,5a,30,2c,31,1d,30,1b,06,03,55,04,03,13,14,42,65,6e,67,62,75,47,\
  75,61,72,64,73,20,52,6f,6f,74,20,43,41,31,0b,30,09,06,03,55,04,06,13,02,43,\
  4e,30,81,9f,30,0d,06,09,2a,86,48,86,f7,0d,01,01,01,05,00,03,81,8d,00,30,81,\
  89,02,81,81,00,cc,d0,b7,ff,08,fc,42,b8,3e,3c,19,e5,1a,a9,58,54,95,da,0d,ab,\
  e9,ad,0c,30,a7,a0,fc,70,ab,0e,31,6e,ce,aa,ab,b0,38,13,97,02,e1,c8,7f,18,32,\
  35,71,d3,90,bb,74,ab,71,be,8e,0c,43,85,6d,4c,40,f3,11,08,93,27,40,da,c8,1a,\
  a4,2c,18,b8,44,a3,ca,e9,4d,08,7c,38,e6,13,cb,87,5f,3a,46,b1,86,83,05,f5,1f,\
  8a,c1,9f,a2,67,83,06,34,2d,83,70,97,b7,73,df,7e,0f,14,83,d2,63,3e,3c,3d,4b,\
  79,90,f2,7a,03,24,04,b5,02,03,01,00,01,a3,61,30,5f,30,5d,06,03,55,1d,01,04,\
  56,30,54,80,10,47,75,49,c1,cf,e2,62,78,ef,ce,30,ec,bd,d2,61,d6,a1,2e,30,2c,\
  31,1d,30,1b,06,03,55,04,03,13,14,42,65,6e,67,62,75,47,75,61,72,64,73,20,52,\
  6f,6f,74,20,43,41,31,0b,30,09,06,03,55,04,06,13,02,43,4e,82,10,42,c5,10,2e,\
  2b,30,6b,98,4a,59,e8,f8,c8,25,f9,80,30,09,06,05,2b,0e,03,02,1d,05,00,03,81,\
  81,00,21,4b,a6,ae,a8,ce,f5,20,65,58,08,1b,cb,ed,39,a2,41,d8,15,96,1b,f6,3b,\
  df,10,c0,9d,c2,5d,c7,33,12,5b,ad,a4,23,16,2b,29,48,e7,4c,61,5a,b8,65,8a,be,\
  d4,38,f9,b8,93,23,d8,05,ec,1f,9c,fc,a4,c1,a4,c9,b6,e0,30,cf,05,7c,ca,01,89,\
  6a,d9,44,34,6a,db,a4,94,bc,4d,95,8c,0d,1b,0d,6c,25,f3,56,0d,18,71,ea,1e,dd,\
  2f,b6,65,8e,8b,18,17,ac,31,b1,e7,93,a8,8a,8a,ff,f1,c2,f1,28,16,7a,1f,df,72,\
  4d,21,9b,9a,7a
)REG";

// 写出临时 reg 文件
bool WriteToolkitRegFile(std::wstring &outPath)
{
    wchar_t tempDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir))
        return false;
    wchar_t tempFile[MAX_PATH];
    if (!GetTempFileNameW(tempDir, L"tkf", 0, tempFile))
        return false;

    outPath = tempFile;
    // 重命名为 .reg 扩展名
    size_t pos = outPath.find_last_of(L'.');
    if (pos != std::wstring::npos)
        outPath = outPath.substr(0, pos) + L".reg";

    FILE *fp = _wfopen(outPath.c_str(), L"wb");
    if (!fp)
        return false;
    fwrite(kToolkitReg, 1, strlen(kToolkitReg), fp);
    fclose(fp);
    return true;
}

// 根据进程名查找所有匹配的 PID
std::vector<DWORD> FindProcessIds(const std::wstring &procName)
{
    std::vector<DWORD> results;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return results;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (procName == entry.szExeFile)
            {
                results.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return results;
}

// 将 DLL 注入指定 PID
bool Inject(DWORD pid, const std::wstring &dllPath, bool topmost, bool anticapture)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "Error: OpenProcess failed, code: " << GetLastError() << std::endl;
        return false;
    }

    SIZE_T size = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteStr = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStr)
    {
        std::cout << "Error: VirtualAllocEx failed, code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteStr, dllPath.c_str(), size, nullptr))
    {
        std::cout << "Error: WriteProcessMemory failed, code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteStr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW),
                                        remoteStr, 0, nullptr);
    if (!hThread)
    {
        std::cout << "Error: CreateRemoteThread failed, code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteStr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD remoteRet = 0;
    GetExitCodeThread(hThread, &remoteRet);

    // Call SetFlags exported function to configure behaviors
    if (remoteRet != 0) // remoteRet 是 DLL 在远程进程中的基址
    {
        HMODULE localMod = LoadLibraryExW(dllPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (localMod)
        {
            FARPROC localFunc = GetProcAddress(localMod, "SetFlags");
            if (localFunc)
            {
                uintptr_t offset = (uintptr_t)localFunc - (uintptr_t)localMod;
                LPTHREAD_START_ROUTINE remoteFunc = (LPTHREAD_START_ROUTINE)((uintptr_t)remoteRet + offset);

                struct Flags { BOOL top; BOOL cap; } flags = { topmost, anticapture };
                LPVOID remoteFlags = VirtualAllocEx(hProcess, nullptr, sizeof(flags), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (remoteFlags)
                {
                    WriteProcessMemory(hProcess, remoteFlags, &flags, sizeof(flags), nullptr);
                    HANDLE hCfgThread = CreateRemoteThread(hProcess, nullptr, 0, remoteFunc, remoteFlags, 0, nullptr);
                    if (hCfgThread)
                    {
                        WaitForSingleObject(hCfgThread, INFINITE);
                        CloseHandle(hCfgThread);
                    }
                    VirtualFreeEx(hProcess, remoteFlags, 0, MEM_RELEASE);
                }
            }
            FreeLibrary(localMod);
        }
    }

    VirtualFreeEx(hProcess, remoteStr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return remoteRet != 0;
}

int wmain(int argc, wchar_t *argv[])
{
    bool topmost = true;
    bool anticapture = true;
    DWORD specificPid = 0;
    std::wstring procName;
    std::wstring dllPath;
    std::wstringstream dllArgs;

    // 解析命令行参数
    if (argc < 2)
    {
        std::cout << "Usage: injector.exe <target_process.exe | -pid PID> [dll_path] [options]\n"
                  << "Options:\n"
                  << "  -notopmost    Disable window topmost\n"
                  << "  -nocapture    Disable anti-capture\n"
                  << "  -pid PID      Inject to specific process ID\n";
        return 0;
    }

    // 检查是否使用 -pid 选项
    if (wcscmp(argv[1], L"-pid") == 0)
    {
        if (argc < 3)
        {
            std::cout << "Error: PID value required after -pid\n";
            return 1;
        }
        specificPid = _wtoi(argv[2]);
        if (specificPid == 0)
        {
            std::cout << "Error: Invalid PID\n";
            return 1;
        }
        // 移动参数，使得后续处理与按进程名注入一致
        argc -= 2;
        for (int i = 1; i < argc; i++)
            argv[i] = argv[i+2];
    }
    else
    {
        procName = argv[1];
    }

    bool dllArgProvided = false;
    if (argc >= 3 && argv[2][0] != L'-')
    {
        dllPath = argv[2];
        dllArgProvided = true;
    }
    else
    {
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        std::wstring dir = selfPath;
        size_t pos = dir.find_last_of(L"\\/");
        if (pos != std::wstring::npos)
            dir = dir.substr(0, pos + 1);
        dllPath = dir + L"InjectDLL.dll";
    }

    int optStart = dllArgProvided ? 3 : 2;

    // 处理选项
    for (int i = optStart; i < argc; i++)
    {
        if (wcscmp(argv[i], L"-notopmost") == 0)
        {
            topmost = false;
            dllArgs << L" -notopmost";
        }
        else if (wcscmp(argv[i], L"-nocapture") == 0)
        {
            anticapture = false;
            dllArgs << L" -nocapture";
        }
        else if (wcscmp(argv[i], L"-pid") == 0 && i+1 < argc)
        {
            specificPid = _wtoi(argv[i+1]);
            i++; // 跳过PID值
        }
    }

    // 检查 DLL 是否存在
    DWORD fileAttr = GetFileAttributesW(dllPath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES)
    {
        std::cout << "Error: DLL file not found: " << std::endl;
        return 1;
    }

    // 获取目标进程ID列表
    std::vector<DWORD> targetPids;
    if (specificPid > 0)
    {
        targetPids.push_back(specificPid);
    }
    else
    {
        targetPids = FindProcessIds(procName);
        if (targetPids.empty())
        {
            std::wcout << L"Process not found: " << procName << std::endl;
            return 1;
        }
    }

    // 如果需要顶置, 先导入 Toolkit_fix.reg
    if (topmost)
    {
        std::wstring regPath;
        if (WriteToolkitRegFile(regPath))
        {
            std::wstring cmd = L"import \"" + regPath + L"\"";
            SHELLEXECUTEINFOW sei{sizeof(sei)};
            sei.lpVerb = L"runas";
            sei.lpFile = L"reg.exe";
            sei.lpParameters = cmd.c_str();
            sei.nShow = SW_HIDE;
            if (ShellExecuteExW(&sei))
            {
                WaitForSingleObject(sei.hProcess, INFINITE);
                CloseHandle(sei.hProcess);
            }
            else
            {
                std::cout << "Warning: Failed to import Toolkit_fix.reg" << std::endl;
            }
            DeleteFileW(regPath.c_str());
        }
        else
        {
            std::cout << "Warning: Cannot create Toolkit_fix.reg temp file" << std::endl;
        }
    }

    // 显示注入信息
    std::cout << "Options: " 
              << (topmost ? "Topmost=ON" : "Topmost=OFF") << ", "
              << (anticapture ? "AntiCapture=ON" : "AntiCapture=OFF") << std::endl;
    
    // 对所有目标进程进行注入
    int successCount = 0;
    for (DWORD pid : targetPids)
    {
        std::cout << "Injecting to PID: " << pid;
        if (!specificPid)
            std::wcout << " (" << procName << ")";
        std::cout << std::endl;
        
        if (Inject(pid, dllPath, topmost, anticapture))
        {
            std::cout << "  Success" << std::endl;
            successCount++;
        }
        else
        {
            std::cout << "  Failed" << std::endl;
        }
    }
    
    std::cout << "Summary: " << successCount << " of " << targetPids.size() 
              << " injections successful" << std::endl;

    return 0;
} 