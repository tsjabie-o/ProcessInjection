# Process Injection
A collection of projects containing source code for different methods of performing **process injection**. Loosely following the blog posts by [Crow](https://www.crow.rip/crows-nest) on the same topic. 

- **ProcessInjection**: Uses the Win32 API to perform the process injection after receiving a PID.
- **NTAPI Injection**: Replaces the Win32 API calls with NTAPI (ntdll) calls for added stealth
- **SysCall_Inject**: Removes API calls altoghether and instead directly uses the syscalls that NTDLL uses. Those calls are written in an assembly file, so you might need to change those to work on your specific system.
- **InjectDLL**: Uses the Win32 API to have another process load a 'malicious' DLL file which executes some arbitrary code.

While still a work in progress, over in [this gitbook](https://xavi-oorthuis.gitbook.io/malware-development) I will eventually write up my own tutorial on ProcessInjection, along with explanation of all the code.
