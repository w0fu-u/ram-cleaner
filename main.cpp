#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <vector>
#include <algorithm>
#include <sstream>
#include <string>
#include <iomanip>

struct ProcessInfo {
    DWORD processID;
    std::wstring processName;
    SIZE_T privateUsage;
};

bool CompareProcessName(const ProcessInfo& a, const ProcessInfo& b) {
    return a.processName < b.processName;
}

void PrintTableHeader() {
    std::wcout << std::left << std::setw(40) << L"Name" << std::right << std::setw(15) << L"ID" << std::setw(15) << L"Usage" << std::endl;
    std::wcout << std::left << std::setw(40) << L"----------------------------------------" << std::right << std::setw(15) << L"---------------" << std::setw(15) << L"---------------------------------" << std::endl;
}

void PrintTableRow(const ProcessInfo& processInfo) {
    std::wcout << std::left << std::setw(40) << processInfo.processName << std::right << std::setw(15) << processInfo.processID << std::setw(15) << processInfo.privateUsage / (1024 * 1024) << L" MB" << std::endl;
}

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

int main() {
    DWORD processes[1024], cbNeeded, processCount;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        // wie viele processe wurden gefunden für die for schleife und i
        processCount = cbNeeded / sizeof(DWORD);

        std::vector<ProcessInfo> processList;

        for (DWORD i = 0; i < processCount; i++) {
            // auf den prozess zugreifen
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

            if (hProcess != NULL) {
                // prozess infos bekommen
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    // process name
                    TCHAR processName[MAX_PATH];
                    if (GetModuleBaseName(hProcess, NULL, processName, sizeof(processName) / sizeof(TCHAR))) {
                        ProcessInfo processInfo;
                        processInfo.processID = processes[i];
                        processInfo.processName = processName;
                        processInfo.privateUsage = pmc.PrivateUsage;
                        processList.push_back(processInfo);
                    }
                    else {
                        // process ID ohne namen wenn kein name
                        ProcessInfo processInfo;
                        processInfo.processID = processes[i];
                        processInfo.privateUsage = pmc.PrivateUsage;
                        processList.push_back(processInfo);
                    }
                }

                // Close the process handle
                CloseHandle(hProcess);
            }
        }

        // processe nach name (a-z) sortieren
        std::sort(processList.begin(), processList.end(), CompareProcessName);


       
        // liste als table printen

        PrintTableHeader();
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_BLUE);
        // pink
        for (const auto& processInfo : processList) {
            PrintTableRow(processInfo);
        }

        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

        std::wcout << L"Geben Sie den Prozessnamen für die Whitelist ein (getrennt durch Kommas): ";
        std::wstring processNameInput;
        std::getline(std::wcin, processNameInput);

        // input und whitelist für name
        std::wstringstream ssNames(processNameInput);
        std::vector<std::wstring> whitelistNames;
        std::wstring name;
        while (ssNames >> name) {
            whitelistNames.push_back(name);
            if (ssNames.peek() == L',')
                ssNames.ignore();
        }

        // input und whitelist für ip
        std::wcout << L"Geben Sie die Prozess-IDs für die Whitelist ein (getrennt durch Kommas): ";
        std::wstring processIDInput;
        std::getline(std::wcin, processIDInput);

        std::wstringstream ssIDs(processIDInput);
        std::vector<DWORD> whitelistIDs;
        DWORD pid;
        while (ssIDs >> pid) {
            whitelistIDs.push_back(pid);
            if (ssIDs.peek() == L',')
                ssIDs.ignore();
        }

        // schließt prozesse ("bereiningt") für nicht whitelisted Prozesse
        for (const auto& processInfo : processList) {
            if (std::find(whitelistNames.begin(), whitelistNames.end(), processInfo.processName) == whitelistNames.end() &&
                std::find(whitelistIDs.begin(), whitelistIDs.end(), processInfo.processID) == whitelistIDs.end()) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processInfo.processID);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        }

        std::wcout << L"Speicher für nicht whitelisted Prozesse bereinigt." << std::endl;
    }
    return 0;
}
