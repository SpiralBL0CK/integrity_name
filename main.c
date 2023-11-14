/*
#ifndef _WINNT_
#define _WINNT_

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201) // named type definition in parentheses
#pragma warning(disable:4214) // bit field types other than int
#endif*
*/

#include <Windows.h>
#include <ole2.h>
#include <iostream>
#include <stdio.h>   
#include <stdlib.h>  
#include <psapi.h> // To get process info
#include <winuser.h>
#include <cstdint>
#include <cstdio>
#include <tchar.h>


using namespace std;

void PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.

    if (hProcess != NULL )
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    // Print the process name and identifier.

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    // Release the handle to the process.

    CloseHandle(hProcess);
}

void ShowProcessIntegrityLevel(DWORD processid)
{
    HANDLE hToken;
    HANDLE hProcess;

    DWORD dwLengthNeeded;
    DWORD dwError = ERROR_SUCCESS;

    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    LPWSTR pStringSid;
    DWORD dwIntegrityLevel;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processid);
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        // Get the Integrity level.
        if (!GetTokenInformation(hToken, TokenIntegrityLevel,
            NULL, 0, &dwLengthNeeded))
        {
            dwError = GetLastError();
            if (dwError == ERROR_INSUFFICIENT_BUFFER)
            {
                pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
                    dwLengthNeeded);
                if (pTIL != NULL)
                {
                    if (GetTokenInformation(hToken, TokenIntegrityLevel,
                        pTIL, dwLengthNeeded, &dwLengthNeeded))
                    {
                        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
                            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
                        {
                            // Low Integrity
                            wprintf(L"Low Process:=> ");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                            dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
                        {
                            // Medium Integrity
                            wprintf(L"Medium Process:=> ");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
                            dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            // High Integrity
                            wprintf(L"High Integrity Process:=> ");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
                        {
                            // System Integrity
                            wprintf(L"System Integrity Process:=> ");
                        }
                    }
                    LocalFree(pTIL);
                }
            }
        }
        CloseHandle(hToken);
    }
}

int EnableDebugPrivilege2() {

    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        std::cout << ("OpenProcessToken fail");
        return 0;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        std::cout << ("LookupPrivilegeValue fail");
        return 0;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        std::cout << ("AdjustTokenPrivileges fail");
        return 0;
    }

    return 1;
}


int main()
{
    EnableDebugPrivilege2();
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            PrintProcessNameAndID(aProcesses[i]);
            ShowProcessIntegrityLevel(aProcesses[i]);
        }
    }

	return 0;
}
