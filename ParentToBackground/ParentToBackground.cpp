#include "stdafx.h"

// The ntdll sections of this code were shamelessly stolen from http://blog.misterfoo.com/2010/07/process-priority-utility.html

#ifdef UNICODE
static std::wstring_convert<std::codecvt_utf8<wchar_t>> wstr;
#else
static struct {
    inline std::string to_bytes(const std::string & s) { return s; }
} wstr;
#endif

typedef NTSTATUS(NTAPI *NtQueryInformationProcessFn)(HANDLE process, ULONG infoClass, LPVOID data, ULONG dataSize, ULONG* outSize);
static NtQueryInformationProcessFn NtQueryInformationProcess;

typedef NTSTATUS(NTAPI *NtSetInformationProcessFn)(HANDLE process, ULONG infoClass, LPCVOID data, ULONG dataSize);
static NtSetInformationProcessFn NtSetInformationProcess;

// these values determined by poking around in the debugger - use at your own risk!
const DWORD ProcessInformationMemoryPriority = 0x27;
const DWORD ProcessInformationIoPriority = 0x21;
const DWORD BackgroundMemoryPriority = 1;
const DWORD BackgroundIoPriority = 0;

struct ProcessInfo
{
    ProcessInfo() :
        id(),
        parent(),
        name(),
        children()
    {
    }

    ProcessInfo(PROCESSENTRY32 entry) :
        id(entry.th32ProcessID),
        parent(entry.th32ParentProcessID),
        name(wstr.to_bytes(entry.szExeFile)),
        children()
    {
    }

    DWORD id;
    DWORD parent;
    std::string name;
    std::set<DWORD> children;
};

static bool GetProcessList(std::map<DWORD, ProcessInfo> & processes)
{
#ifdef _DEBUG
    std::cout << "Listing processes..." << std::endl;
#endif
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &entry))
    {
#ifdef _DEBUG
        DWORD err = GetLastError();
        std::cerr << "Could not list processes. Error: " << err << std::endl;
#endif
        CloseHandle(snapshot);
        return false;
    }

    do
    {
        ProcessInfo info(entry);
#ifdef _DEBUG
        std::cout << "Process " << info.id << " (parent: " << info.parent << "): " << info.name << std::endl;
#endif
        processes[info.id] = info;
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);

#ifdef _DEBUG
    std::cout << "Setting child process IDs." << std::endl;
#endif

    for (auto & info : processes)
    {
        if (info.first != 0)
        {
            if (processes.count(info.second.parent))
            {
                processes.at(info.second.parent).children.insert(info.first);
            }
            else
            {
                info.second.parent = 0;
            }
        }
    }

    return true;
}

static bool FindParentNamed(const std::map<DWORD, ProcessInfo> & processes, DWORD & pid, const std::string & name)
{
#ifdef _DEBUG
    std::cout << "Trying to find parent of " << pid << " with name: " << name << std::endl;
#endif

    do
    {
        auto & info = processes.at(pid);
#ifdef _DEBUG
        std::cout << "Checking process " << pid << " \"" << info.name << "\" with parent " << info.parent << std::endl;
#endif
        if (info.name == name)
        {
            return true;
        }

        pid = info.parent;
    } while (pid != 0);

    return false;
}

static bool SetProcessToBackground(const ProcessInfo & info)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION, FALSE, info.id);
    if (!process)
    {
        DWORD err = GetLastError();
        std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (OpenProcess) Error: " << err << std::endl;
        return false;
    }

    DWORD cpuPriority = GetPriorityClass(process);
    if (cpuPriority != IDLE_PRIORITY_CLASS)
    {
        if (!SetPriorityClass(process, IDLE_PRIORITY_CLASS))
        {
            DWORD err = GetLastError();
            std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (SetPriorityClass) Error: " << err << std::endl;
            CloseHandle(process);
            return false;
        }
        std::cout << "Set process " << info.id << " \"" << info.name << "\"" << " CPU priority to background (" << IDLE_PRIORITY_CLASS << ", was " << cpuPriority << ")" << std::endl;
    }

    DWORD memoryPriority;
    ULONG len;
    NTSTATUS result = NtQueryInformationProcess(process, ProcessInformationMemoryPriority, &memoryPriority, sizeof(DWORD), &len);
    if (!result && len == sizeof(DWORD))
    {
        if (memoryPriority != BackgroundMemoryPriority)
        {
            result = NtSetInformationProcess(process, ProcessInformationMemoryPriority, &BackgroundMemoryPriority, sizeof(DWORD));
            if (result)
            {
                std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (NtSetInformationProcess - memory priority) Error: " << result << std::endl;
                CloseHandle(process);
                return false;
            }
            std::cout << "Set process " << info.id << " \"" << info.name << "\"" << " Memory priority to background (" << BackgroundMemoryPriority << ", was " << memoryPriority << ")" << std::endl;
        }
    }
    else
    {
        std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (NtQueryInformationProcess - memory priority) Error: " << result << std::endl;
        CloseHandle(process);
        return false;
    }

    DWORD ioPriority;
    result = NtQueryInformationProcess(process, ProcessInformationIoPriority, &ioPriority, sizeof(DWORD), &len);
    if (!result && len == sizeof(DWORD))
    {
        if (ioPriority != BackgroundIoPriority)
        {
            result = NtSetInformationProcess(process, ProcessInformationIoPriority, &BackgroundIoPriority, sizeof(DWORD));
            if (result)
            {
                std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (NtSetInformationProcess - io priority) Error: " << result << std::endl;
                CloseHandle(process);
                return false;
            }
            std::cout << "Set process " << info.id << " \"" << info.name << "\"" << " IO priority to background (" << BackgroundIoPriority << ", was " << ioPriority << ")" << std::endl;
        }
    }
    else
    {
        std::cerr << "Could not set process " << info.id << " \"" << info.name << "\" to background. (NtQueryInformationProcess - io priority) Error: " << result << std::endl;
        CloseHandle(process);
        return false;
    }

    CloseHandle(process);
    return true;
}

static bool SetProcessTreeToBackground(const std::map<DWORD, ProcessInfo> & processes, DWORD pid)
{
    auto & info = processes.at(pid);

    bool allOK = true;

    if (!SetProcessToBackground(info))
    {
        std::cerr << "Failed to set process to background: " << pid << " \"" << info.name << "\"" << std::endl;
        allOK = false;
    }

    for (auto & child : info.children)
    {
        if (!SetProcessTreeToBackground(processes, child))
        {
            allOK = false;
        }
    }

    return allOK;
}

int main(int argc, char *argv[])
{
    HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
    NtQueryInformationProcess = (NtQueryInformationProcessFn)GetProcAddress(ntdll, "NtQueryInformationProcess");
    NtSetInformationProcess = (NtSetInformationProcessFn)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!NtQueryInformationProcess || !NtSetInformationProcess)
    {
        printf("Failed to locate the required imports from ntdll.dll\n");
        return 1;
    }

    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " NameOfProcess.exe" << std::endl;
        return EXIT_FAILURE;
    }

    std::map<DWORD, ProcessInfo> processes;
    if (!GetProcessList(processes))
    {
        std::cerr << "Could not list processes!" << std::endl;
        return EXIT_FAILURE;
    }

    DWORD pid = GetCurrentProcessId();
    if (!FindParentNamed(processes, pid, argv[1]))
    {
        std::cerr << "Could not find parent process with name: " << argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    if (!SetProcessTreeToBackground(processes, pid))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
