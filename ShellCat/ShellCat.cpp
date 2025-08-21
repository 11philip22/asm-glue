#include <cstdio>
#include <fstream>
#include <Windows.h>

static bool LoadShellcode(const char* filename, char*& outBuffer, unsigned long& outLength)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size <= 0)
        return false;

    outBuffer = (char*)malloc(size);
    if (!outBuffer)
        return false;

    if (!file.read(outBuffer, size)) {
        free(outBuffer);
        outBuffer = nullptr;
        return false;
    }

    outLength = static_cast<unsigned int>(size);
    return true;
}

static void ShellCat(char* shellcodeA, unsigned long shellcodeALength,
                     char* shellcodeB, unsigned long shellcodeBLength,
                     char*& outBytes, unsigned long& outLength)
{
#if defined(_WIN64)
    BYTE bootstrap[32] = { 0 };
    size_t i = 0;

    // push rbp
    bootstrap[i++] = 0x55;

    // mov rbp, rsp
    bootstrap[i++] = 0x48;
    bootstrap[i++] = 0x89;
    bootstrap[i++] = 0xE5;

    // sub rsp, 0x20
    bootstrap[i++] = 0x48;
    bootstrap[i++] = 0x83;
    bootstrap[i++] = 0xEC;
    bootstrap[i++] = 0x20;

    // call - Transfer execution to shellCodeA
    bootstrap[i++] = 0xE8;
    unsigned int shellcodeAOffset = sizeof(bootstrap) - i - 4;
    bootstrap[i++] = (BYTE)shellcodeAOffset;
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 8);
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 16);
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 24);

    // add rsp, 0x20
    bootstrap[i++] = 0x48;
    bootstrap[i++] = 0x83;
    bootstrap[i++] = 0xC4;
    bootstrap[i++] = 0x20;

    // sub rsp, 0x20
    bootstrap[i++] = 0x48;
    bootstrap[i++] = 0x83;
    bootstrap[i++] = 0xEC;
    bootstrap[i++] = 0x20;

    // call - Transfer execution to shellCodeB
    bootstrap[i++] = 0xE8;
    unsigned int shellcodeBOffset = sizeof(bootstrap) + shellcodeALength - i - 4;
    bootstrap[i++] = (BYTE)shellcodeBOffset;
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 8);
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 16);
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 24);

    // add rsp, 0x20
    bootstrap[i++] = 0x48;
    bootstrap[i++] = 0x83;
    bootstrap[i++] = 0xC4;
    bootstrap[i++] = 0x20;

    // leave
    bootstrap[i++] = 0xC9;

    // ret - return to caller
    bootstrap[i++] = 0xC3;

    outLength = sizeof(bootstrap) + shellcodeALength + shellcodeBLength;
    outBytes = (char*)malloc(outLength);
    MoveMemory(outBytes, bootstrap, sizeof(bootstrap));
    MoveMemory(outBytes + sizeof(bootstrap), shellcodeA, shellcodeALength);
    MoveMemory(outBytes + sizeof(bootstrap) + shellcodeALength, shellcodeB, shellcodeBLength);
#else
    BYTE bootstrap[12] = { 0 };
    unsigned int i = 0;

    // call - Transfer execution to shellCodeA
    bootstrap[i++] = 0xe8;
    unsigned int shellcodeAOffset = sizeof(bootstrap) - i - 4;
    bootstrap[i++] = (BYTE)shellcodeAOffset;
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 8);
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 16);
    bootstrap[i++] = (BYTE)(shellcodeAOffset >> 24);

    // call - Transfer execution to shellCodeB
    bootstrap[i++] = 0xe8;
    unsigned int shellcodeBOffset = sizeof(bootstrap) + shellcodeALength - i - 4;
    bootstrap[i++] = (BYTE)shellcodeBOffset;
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 8);
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 16);
    bootstrap[i++] = (BYTE)(shellcodeBOffset >> 24);

    // leave
    bootstrap[i++] = 0xc9;

    // ret - return to caller
    bootstrap[i++] = 0xc3;

    outLength = sizeof(bootstrap) + shellcodeALength + shellcodeBLength;
    outBytes = (char*)malloc(outLength);
    MoveMemory(outBytes, bootstrap, sizeof(bootstrap));
    MoveMemory(outBytes + sizeof(bootstrap), shellcodeA, shellcodeALength);
    MoveMemory(outBytes + sizeof(bootstrap) + shellcodeALength, shellcodeB, shellcodeBLength);
#endif
}

typedef UINT_PTR(WINAPI* SHC)();

int main()
{
#if defined(_WIN64)
	const char* shellcodeAPath = "../bin/ShellcodeA_x64.bin";
	const char* shellcodeBPath = "../bin/ShellcodeB_x64.bin";
#else
	const char* shellcodeAPath = "../bin/ShellcodeA_x86.bin";
	const char* shellcodeBPath = "../bin/ShellcodeB_x86.bin";
#endif

    // Load shellcode A
    char* shellcodeA = nullptr;
    unsigned long shellcodeALength = 0;
    bool status = LoadShellcode(shellcodeAPath, shellcodeA, shellcodeALength);
    if (!status) 
    {
        printf("[!] Failed to load shellcode A\n");
		return 1;
    }

    // Load shellcode B
	char* shellcodeB = nullptr;
	unsigned long shellcodeBLength = 0;
    status = LoadShellcode(shellcodeBPath, shellcodeB, shellcodeBLength);
    if (!status) 
    {
        printf("[!] Failed to load shellcode B\n");
        
		free(shellcodeA);
		return 1;
    }

    // Pass loaded shellcodes to ConvertToShellcode
    char* finalShellcode = NULL;
    unsigned long finalSize = 0;
    ShellCat(shellcodeA, shellcodeALength, shellcodeB, shellcodeBLength, finalShellcode, finalSize);
    if (!status) 
    {
        printf("[!] Failed to convert shellcode\n");
        
		free(shellcodeA);
        free(shellcodeB);
		return 1;
    }

    std::fstream outFile;
    outFile = std::fstream(R"(../bin/FinalShellcode_x86.bin)",
        std::ios::out | std::ios::binary);
    outFile.write(finalShellcode, finalSize);
    outFile.close();

    SYSTEM_INFO sysInfo = { 0 };
    GetNativeSystemInfo(&sysInfo);

    unsigned long dwOldProtect = 0;
    if (VirtualProtect(finalShellcode, sysInfo.dwPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect) != TRUE)
    {
		printf("[!] Failed to change memory protection\n");

        free(shellcodeA);
        free(shellcodeB);
        free(finalShellcode);
		return 1;
    }

    SHC shc = (SHC)(finalShellcode);

    printf("[+] Executing shell code\n");
    HMODULE hLoadedShc = (HMODULE)shc(); // Execute shellcode

    free(shellcodeA);
    free(shellcodeB);
    free(finalShellcode);
    return 0;
}