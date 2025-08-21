# ShellCat

A small C++ utility for **concatenating two shellcode binaries** into a single executable shellcode blob.  
It generates a bootstrap stub that first calls `ShellcodeA`, then `ShellcodeB`, and finally returns to the caller.

## Overview

The program:
1. Loads two shellcode files (`ShellcodeA` and `ShellcodeB`) from disk.  
2. Builds a small bootstrap code stub that ensures proper stack setup and execution flow.  
   - On **x64**, the stub adjusts `RSP`, calls `ShellcodeA`, realigns the stack, then calls `ShellcodeB`.  
   - On **x86**, the stub simply calls `ShellcodeA` then `ShellcodeB`.  
3. Concatenates the bootstrap + `ShellcodeA` + `ShellcodeB` into one final binary.  
4. Saves the resulting shellcode into `FinalShellcode_x86.bin` (or `FinalShellcode_x64.bin` depending on target).  
5. Uses `VirtualProtect` to make the memory executable and runs the final shellcode.

## Build

Compile with MSVC (x86 or x64):

## Notes

- Uses VirtualProtect to mark the concatenated shellcode as executable.
- The bootstrap code ensures stack alignment before transferring control.

## Disclaimer

This project is for educational and research purposes only.
Do not use it for malicious activity. The author assumes no responsibility for improper use.