// HttpClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "json.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <versionhelpers.h>
#include <tlhelp32.h>
#include <curl/curl.h>
#include <iostream>  // 引入标准输入输出库
#undef max
#include <limits>
#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <ctime>
#include <bitset>
#include <cstring>

#include <iphlpapi.h>

#include <fstream>
#include <vector>
#include <locale>
#include <codecvt>
#include <chrono>

#include "report.h"

using namespace std;

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"Advapi32.lib")


std::string user_key = "";
std::string user_hwid = "";
std::string url = "https://anticheatexpert.co";



#define MAX_SIGNATURE_LENGTH 256

std::string xor_encrypt(const std::string& input, const std::string& key) {
	std::string encrypted = input;
	size_t key_length = key.length();

	for (size_t i = 0; i < input.length(); ++i) {

		encrypted[i] = input[i] ^ key[i % key_length];
	}
	return encrypted;
}

std::string xor_decrypt(const std::string& input, const std::string& key) {
	return xor_encrypt(input, key);
}


//Expirationtime 剩余秒数数写入shellcode校验
//cpExeFile shellcode文件位置
bool inject(IN LONG Expirationtime, IN CONST WCHAR* cpExeFile)
{
	HWND    hWnd = NULL;
	HANDLE  hFile = NULL;
	HANDLE  hMapping = NULL;
	HANDLE  hProcess = NULL;
	PVOID   lpBuffer = NULL;
	DWORD   dwProcessId = 0;

	CHAR    strClassName[] = { 'U', 'n' ,'i','t','y','W','n','d','C','l','a','s','s','\0' };
	CHAR    strWindowName[] = { 'N', 'a' ,'r','a','k','a','\0' };
	CHAR    cpInterFacefnName[] = "X";

	hWnd = FindWindowA(strClassName, strWindowName);
	if (hWnd == NULL) {
		printf("[-] failed FindWindowA code:%d\n", GetLastError());
		return 0;
	}
	if (GetWindowThreadProcessId(hWnd, &dwProcessId) == 0) {
		printf("[-] failed GetWindowThreadProcessId code:%d\n", GetLastError());
		return 0;
	}
	hFile = CreateFileW(cpExeFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] failed CreateFileA code:%d\n", GetLastError());
		return 0;
	}
	hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL) {
		printf("[-] failed CreateFileMappingA code:%d\n", GetLastError());
		return 0;
	}

	lpBuffer = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!lpBuffer) {
		printf("[-] failed MapViewOfFile code:%d\n", GetLastError());
		return 0;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("[-] failed OpenProcess code:%d\n", GetLastError());
		return 0;
	}
	ULONG_PTR                   BaseAddress = 0;
	PIMAGE_DOS_HEADER           pDosHdr = NULL;
	PIMAGE_NT_HEADERS           pNtHdr = NULL;
	PVOID                       pRemote = NULL;
	SIZE_T                      lpNumberOfBytesRead = 0;
	PVOID                       lpInterFace = NULL;

	BaseAddress = (ULONG_PTR)lpBuffer;
	pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		//no pe file
		MessageBoxW(NULL, L"This is not PE file", L"Failed", MB_ICONERROR | MB_OK);
		return 0;
	}
	pNtHdr = (PIMAGE_NT_HEADERS)(BaseAddress + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		//no pe file
		MessageBoxW(NULL, L"This is not PE file", L"Failed", MB_ICONERROR | MB_OK);
		return 0;
	}
	if (pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		//no PE64
		MessageBoxW(NULL, L"This file is not PE64", L"Failed", MB_ICONERROR | MB_OK);
		return 0;
	}
	pRemote = VirtualAllocEx(hProcess, NULL, (SIZE_T)pNtHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pRemote == NULL) {
		printf("[-] failed VirtualAllocEx code:%d\n", GetLastError());
		return 0;
	}
	PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);
	for (INT i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
		if (!WriteProcessMemory(
			hProcess,
			(PVOID)((ULONG_PTR)pRemote + pSectionHdr[i].VirtualAddress),
			(PVOID)(BaseAddress + pSectionHdr[i].VirtualAddress),//CreateFileMappingA->SEC_IMAGE
			pSectionHdr[i].SizeOfRawData,
			&lpNumberOfBytesRead)) {
			return 0;
		}
	}
	//get inject interface
	IMAGE_DATA_DIRECTORY exportDir = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.Size) {
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + exportDir.VirtualAddress);
		PULONG AddressOfNames = (PULONG)(pExport->AddressOfNames + BaseAddress);
		PULONG AddressOfFunctions = (PULONG)(pExport->AddressOfFunctions + BaseAddress);
		PWORD AddressOfNameOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + BaseAddress);
		//只需关注按名称导出函数
		for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
			CHAR* cpFunctionName = (CHAR*)(BaseAddress + AddressOfNames[i]);
			if (strcmp(cpFunctionName, cpInterFacefnName) == 0) {
				lpInterFace = (PVOID)((ULONG_PTR)pRemote + AddressOfFunctions[AddressOfNameOrdinals[i]]);
			}
		}
	}
	if (lpInterFace == NULL) {
		MessageBoxW(NULL, L"Dont' find InterFace", L"Failed", MB_ICONERROR | MB_OK);
		return 0;
	}
	IMAGE_DATA_DIRECTORY importDir = (IMAGE_DATA_DIRECTORY)pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.Size) {
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(BaseAddress + importDir.VirtualAddress);
		while (pImport->Name) {
			CHAR* cpDllName = (CHAR*)(BaseAddress + pImport->Name);
			HMODULE hModule = LoadLibraryA(cpDllName);
			if (hModule == NULL) {
				return 0;
			}
			//INT
			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)(BaseAddress + pImport->OriginalFirstThunk);
			//IAT
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)(BaseAddress + pImport->FirstThunk);
			while (OriginalFirstThunk->u1.AddressOfData) {
				if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					// 按序号导入
					//MessageBoxA(NULL, "has IMAGE_ORDINAL_FLAG ", "failed", MB_OK);
				}
				else {
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(BaseAddress + FirstThunk->u1.AddressOfData);
					FARPROC Function = GetProcAddress(hModule, pImportByName->Name);
					if (Function == NULL) {
						return 0;
					}
					if (!WriteProcessMemory(hProcess,
						(PVOID)((ULONG_PTR)pRemote + pImport->FirstThunk),
						&Function,
						sizeof(FARPROC),
						&lpNumberOfBytesRead)) {
						return 0;
					}
				}
				OriginalFirstThunk++;
				FirstThunk++;
			}
			pImport = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pImport + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
	}
	IMAGE_DATA_DIRECTORY relocDir = (IMAGE_DATA_DIRECTORY)pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir.Size) {
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(BaseAddress + relocDir.VirtualAddress);
		while (pReloc->SizeOfBlock) {
			DWORD dwCont = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD pEntry = (PWORD)((ULONG_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < dwCont; i++) {
				WORD Type = pEntry[i] >> 12;
				WORD Offset = pEntry[i] & 0xFFF;
				if (Type == IMAGE_REL_BASED_DIR64)
				{
					ULONG_PTR Address = *(ULONG_PTR*)(BaseAddress + pReloc->VirtualAddress + Offset);
					Address = Address - BaseAddress + (ULONG_PTR)pRemote;
					if (!WriteProcessMemory(hProcess,
						(PVOID)((ULONG_PTR)pRemote + pReloc->VirtualAddress + Offset),
						&Address,
						sizeof(ULONG_PTR),
						&lpNumberOfBytesRead)) {
						return 0;
					}
				}
				else if (Type == IMAGE_REL_BASED_HIGHLOW) {
					MessageBoxA(NULL, "has IMAGE_REL_BASED_HIGHLOW ", "failed", MB_OK);
					return 0;
				}
				else if (Type == IMAGE_REL_BASED_HIGH) {
					MessageBoxA(NULL, "has IMAGE_REL_BASED_HIGH ", "failed", MB_OK);
					return 0;
				}
				else if (Type == IMAGE_REL_BASED_LOW) {
					MessageBoxA(NULL, "has IMAGE_REL_BASED_LOW ", "failed", MB_OK);
					return 0;
				}
			}
			pReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pReloc + pReloc->SizeOfBlock);
		}
	}
	if (lpBuffer)
		UnmapViewOfFile(lpBuffer);
	if (hMapping)
		CloseHandle(hMapping);
	if (hFile)
		CloseHandle(hFile);
	//get module base

	HANDLE hModuleSnap = NULL;
	MODULEENTRY32 me32 = { 0 };
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32)) {
		return FALSE;
	}
	do
	{
		if (strcmp(me32.szModule, "GameAssembly.dll") == NULL) {
			UCHAR lpBuffer[8];
			if (ReadProcessMemory(hProcess, (PUCHAR)lpInterFace + 0x90, &lpBuffer, sizeof(lpBuffer), &lpNumberOfBytesRead))
			{
				if (lpBuffer[0] == 0xFF && lpBuffer[1] == 0xFF && lpBuffer[2] == 0xFF && lpBuffer[3] == 0xFF &&
					lpBuffer[4] == 0xFF && lpBuffer[5] == 0xFF && lpBuffer[6] == 0xFF && lpBuffer[7] == 0xFF)
				{
					LONG64 Time = Expirationtime;
					if (!WriteProcessMemory(hProcess, (PUCHAR)lpInterFace + 0x90, &Time, sizeof(LONG64), &lpNumberOfBytesRead)) {
						MessageBoxA(NULL, "failed1", "", NULL);
						return 0;
					}
				}
			}
			if (!WriteProcessMemory(hProcess, (PVOID)((ULONG_PTR)me32.modBaseAddr + 0xC5D54E0), &lpInterFace, sizeof(PVOID), &lpNumberOfBytesRead)) {
				MessageBoxA(NULL, "failed", "", NULL);
				return 0;
			}
			MessageBoxA(NULL, "Success", "", MB_OK);
			break;
		}
	} while (Module32Next(hModuleSnap, &me32));
	if (hModuleSnap)
		CloseHandle(hModuleSnap);
	if (hProcess)
		CloseHandle(hProcess);
	return true;
}


DWORD VirtualToFileOffset(DWORD VirtualAddress, BYTE*& lpBuffer)
{
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	pNtHeaders = (PIMAGE_NT_HEADERS)(lpBuffer + ((PIMAGE_DOS_HEADER)lpBuffer)->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (VirtualAddress < pSectionHeader[0].PointerToRawData)
		return VirtualAddress;
	for (size_t i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (VirtualAddress >= pSectionHeader[i].VirtualAddress && VirtualAddress < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
			return (VirtualAddress - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
	}
	return 0;
}


std::string getCurrentTime() {
	// 获取当前时间点
	auto now = std::chrono::system_clock::now();

	// 转换为系统时间 (std::time_t)
	std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);

	// 转换为结构体 tm
	std::tm tm;
	if (localtime_s(&tm, &now_time_t) != 0) {
		// 如果转换失败，可以选择返回一个空字符串或其他错误标识
		return "Error: Unable to convert time";
	}

	// 格式化时间并返回字符串
	std::ostringstream oss;
	oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
	return oss.str();
}

void console_log(std::string text, BOOLEAN level) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	switch (level) {
		
	case true:
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN); // 绿色
		break;
	case false:
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED); // 红色
		break;
	}



	std::cout << "\r\n" << "[" + getCurrentTime() + "]" << (level ? "[SUCCESS]   " : "[ERROR]   ") << text << std::endl;

}
bool inject_naraka(const std::string& key, BYTE*& lpBuffer, int cheat_addr1, int cheat_addr2, int cheat_addr3, LONG Expirationtime, std::string& cardkey, std::string& signature)
{
	bool result = false;
	HWND hWnd = NULL;
	CHAR strClassName[] = { 'U', 'n' ,'i','t','y','W','n','d','C','l','a','s','s','\0' };
	CHAR strWindowName[] = { 'N', 'a' ,'r','a','k','a','\0' };

	hWnd = FindWindowA(strClassName, strWindowName);
	if (hWnd == NULL) {
		std::cerr << "\r\n请先打开游戏!" << std::endl;
		return false;
	}
	DWORD dwProcessId = 0;
	if (GetWindowThreadProcessId(hWnd, &dwProcessId) == 0) {

		std::cerr << "\r\n获取游戏信息失败" << std::endl;
		return false;
	}
	ULONG_PTR GameAssemblyDll = 0, UnityPlayerDll = 0, UnityPlayer_LVBDll = 0;
	//获取gameassembly.dll
	HANDLE hModuleSnap = NULL;
	MODULEENTRY32 me32 = { 0 };
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hModuleSnap != INVALID_HANDLE_VALUE) {
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hModuleSnap, &me32)) {
			do
			{
				if (strcmp(me32.szModule, "GameAssembly.dll") == NULL) {
					GameAssemblyDll = (ULONG_PTR)me32.modBaseAddr;
				}
				if (strcmp(me32.szModule, "UnityPlayer.dll") == NULL) {
					UnityPlayerDll = (ULONG_PTR)me32.modBaseAddr;
				}
				if (strcmp(me32.szModule, "UnityPlayer_LVB.dll") == NULL) {
					UnityPlayer_LVBDll = (ULONG_PTR)me32.modBaseAddr;
				}
			} while (Module32Next(hModuleSnap, &me32));
		}
		CloseHandle(hModuleSnap);
	}
	if (GameAssemblyDll == 0 || (UnityPlayerDll == 0 && UnityPlayer_LVBDll == 0)) {
		std::cerr << "\r\nFailed GameInfoData" << std::endl;
		return false;
	}
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lpBuffer;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		//no pe file
		std::cerr << "\r\n严重内部错误" << std::endl;
		return false;
	}
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(lpBuffer + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		//no pe file
		std::cerr << "\r\n严重内部错误" << std::endl;
		return false;
	}
	if (pNtHdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		//no PE64
		std::cerr << "\r\n严重内部错误" << std::endl;
		return false;
	}
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		std::cerr << "\r\n打开游戏进程失败" << std::endl;
		return false;
	}
	//校验写入shellcode地址是否合法
	SIZE_T lpNumberOfBytesRead;
	ULONG_PTR ShellCodeAddress = 0;
	if (!ReadProcessMemory(hProcess, (PUCHAR)(GameAssemblyDll + cheat_addr1), &ShellCodeAddress, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		std::cerr << "\r\n读取游戏数据失败" << std::endl;
		return false;
	}
	ULONG_PTR UnityPlayerDllBase = UnityPlayerDll + cheat_addr2;
	ULONG_PTR UnityPlayer_LVBDllBase = UnityPlayer_LVBDll + cheat_addr3;
	//地址已经被修改过，要求重启游戏
	if (ShellCodeAddress != UnityPlayerDllBase && ShellCodeAddress != UnityPlayer_LVBDllBase)
	{
		std::cerr << "\r\n游戏数据异常,请重启游戏后再次尝试" << std::endl;
		return false;
	}
	PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pNtHdr->OptionalHeader + pNtHdr->FileHeader.SizeOfOptionalHeader);
	PVOID lpRemote = VirtualAllocEx(hProcess, NULL, (SIZE_T)pNtHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpRemote == NULL) {
		std::cerr << "\r\n远程操作失败" << std::endl;
		CloseHandle(hProcess);
		return false;
	}
	for (INT i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
		if (!WriteProcessMemory(
			hProcess,
			(PVOID)((ULONG_PTR)lpRemote + pSectionHdr[i].VirtualAddress),
			(PVOID)(lpBuffer + VirtualToFileOffset(pSectionHdr[i].VirtualAddress, lpBuffer)),
			pSectionHdr[i].SizeOfRawData,
			&lpNumberOfBytesRead)) {
			CloseHandle(hProcess);
			return false;
		}
	}
	PVOID lpInterFace = NULL;
	IMAGE_DATA_DIRECTORY exportDir = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDir.Size) {
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(lpBuffer + VirtualToFileOffset(exportDir.VirtualAddress, lpBuffer));
		if (pExport->NumberOfNames)
		{
			PULONG AddressOfNames = (PULONG)(lpBuffer + VirtualToFileOffset(pExport->AddressOfNames, lpBuffer));
			PULONG AddressOfFunctions = (PULONG)(lpBuffer + VirtualToFileOffset(pExport->AddressOfFunctions, lpBuffer));
			PWORD AddressOfNameOrdinals = (PWORD)(lpBuffer + VirtualToFileOffset(pExport->AddressOfNameOrdinals, lpBuffer));
			for (SIZE_T i = 0; i < pExport->NumberOfNames; i++) {
				CHAR* cpFunctionName = (CHAR*)(lpBuffer + VirtualToFileOffset(AddressOfNames[i], lpBuffer));
				if (strcmp(cpFunctionName, "X") == 0) {
					lpInterFace = (PVOID)((ULONG_PTR)lpRemote + AddressOfFunctions[AddressOfNameOrdinals[i]]);
				}
			}
		}
	}
	//std::cout << "lpInterFace" << lpInterFace << std::endl;
	//std::cout << "lpRemote" << lpRemote << std::endl;
	IMAGE_DATA_DIRECTORY relocDir = (IMAGE_DATA_DIRECTORY)pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocDir.Size) {
		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(lpBuffer + VirtualToFileOffset(relocDir.VirtualAddress, lpBuffer));
		while (pReloc->SizeOfBlock) {
			DWORD dwCont = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD pEntry = (PWORD)((ULONG_PTR)pReloc + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < dwCont; i++) {
				WORD Type = pEntry[i] >> 12;
				WORD Offset = pEntry[i] & 0xFFF;
				if (Type == IMAGE_REL_BASED_DIR64)
				{
					ULONG_PTR lpAddress = *(ULONG_PTR*)((ULONG_PTR)lpBuffer + VirtualToFileOffset(pReloc->VirtualAddress, lpBuffer) + Offset) -
						pNtHdr->OptionalHeader.ImageBase + (ULONG_PTR)lpRemote;
					if (!WriteProcessMemory(hProcess,
						(PVOID)((ULONG_PTR)lpRemote + pReloc->VirtualAddress + Offset),
						&lpAddress,
						sizeof(ULONG_PTR),
						&lpNumberOfBytesRead)) {
						return 0;
					}
				}
			}
			pReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pReloc + pReloc->SizeOfBlock);
		}
	}
	UCHAR lpBuffers[8];
	if (ReadProcessMemory(hProcess, (PUCHAR)lpInterFace + 0x90, &lpBuffers, sizeof(lpBuffers), &lpNumberOfBytesRead))
	{
		if (lpBuffers[0] == 0xFF && lpBuffers[1] == 0xFF && lpBuffers[2] == 0xFF && lpBuffers[3] == 0xFF &&
			lpBuffers[4] == 0xFF && lpBuffers[5] == 0xFF && lpBuffers[6] == 0xFF && lpBuffers[7] == 0xFF)
		{
			//写入剩余时间
			LONG64 Times = Expirationtime ^ 0xDEADBEEF;
			if (WriteProcessMemory(hProcess, (PUCHAR)lpInterFace + 0x90, &Times, sizeof(LONG64), &lpNumberOfBytesRead)) {
				//读取carkkey偏移
				LONG CarkKeyOffset = 0;
				if (ReadProcessMemory(hProcess, (PUCHAR)lpInterFace + 0x9B, &CarkKeyOffset, sizeof(LONG), &lpNumberOfBytesRead)) {
					//写入cardkey
					std::string cardkey_ = cardkey;
					cardkey_ = xor_encrypt(cardkey, key);
					ULONG_PTR CarkKeyAddress = (ULONG_PTR)lpInterFace + 0x9F + CarkKeyOffset;
					if (WriteProcessMemory(hProcess, (PVOID)CarkKeyAddress, cardkey_.c_str(), cardkey_.size() + 1, &lpNumberOfBytesRead)) {
						//读取Signature偏移
						LONG SignatureOffset = 0;
						if (ReadProcessMemory(hProcess, (PUCHAR)lpInterFace + 0xA2, &SignatureOffset, sizeof(LONG), &lpNumberOfBytesRead)) {
							//写入Signature
							std::string signature_ = signature;
							signature_ = xor_encrypt(signature, key);
							ULONG_PTR SignatureAddress = (ULONG_PTR)lpInterFace + 0xA6 + SignatureOffset;
							if (WriteProcessMemory(hProcess, (PVOID)SignatureAddress, signature_.c_str(), signature_.size() + 1, &lpNumberOfBytesRead)) {
								//写入shell
								if (WriteProcessMemory(hProcess, (PVOID)(GameAssemblyDll + cheat_addr1), &lpInterFace, sizeof(PVOID), &lpNumberOfBytesRead)) {
									result = true;
								}
							}
						}
					}
				}
			}
		}
	}
	if (hProcess)
		CloseHandle(hProcess);
	return result;
}

bool get_wechat_processid(DWORD* processid, ULONG_PTR* modBaseAddr)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	bool bFind = false;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return FALSE;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		//printError(TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return(FALSE);
	}
	do
	{
		if (strcmp(pe32.szExeFile, "Weixin.exe") == 0)
		{
			//printf("pe32.szExeFile:[%s]\n", pe32.szExeFile);
			HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
			MODULEENTRY32 me32;

			hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
			if (hModuleSnap == INVALID_HANDLE_VALUE)
			{
				//printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
				continue;
			}
			me32.dwSize = sizeof(MODULEENTRY32);
			if (!Module32First(hModuleSnap, &me32))
			{
				//printError(TEXT("Module32First"));
				CloseHandle(hModuleSnap);
				continue;
			}
			do
			{
				if (strcmp(me32.szModule, "Weixin.dll") == NULL) {
					*modBaseAddr = (ULONG_PTR)me32.modBaseAddr;
					*processid = pe32.th32ProcessID;
					bFind = true;
					break;
				}
			} while (Module32Next(hModuleSnap, &me32));
			CloseHandle(hModuleSnap);
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return bFind;
}

bool get_process_string(HANDLE hProcess, PVOID lpBaseAddress, std::string& result)
{
	ULONG_PTR Address = (ULONG_PTR)lpBaseAddress;
	SIZE_T length;
	SIZE_T lpNumberOfBytesRead;
	if (ReadProcessMemory(hProcess, (PVOID)(Address + 16), &length, sizeof(SIZE_T), &lpNumberOfBytesRead))
	{
		char* buffer = new char[length + 1];
		if (length >= 16)
		{
			if (ReadProcessMemory(hProcess, (PVOID)Address, &Address, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
			{
				if (ReadProcessMemory(hProcess, (PVOID)Address, buffer, length, &lpNumberOfBytesRead))
				{
					buffer[lpNumberOfBytesRead] = '\0';
					result.assign(buffer);
					delete[] buffer;
					return true;
				}
			}
		}
		else
		{
			if (ReadProcessMemory(hProcess, (PVOID)Address, buffer, length, &lpNumberOfBytesRead))
			{
				buffer[lpNumberOfBytesRead] = '\0';
				result.assign(buffer);
				delete[] buffer;
				return true;
			}
		}
		delete[] buffer;
	}
	return false;
}

int get_wechat_contact_count(HANDLE hProcess, PVOID lpBaseAddress)
{
	ULONG_PTR lpBuffer = (ULONG_PTR)lpBaseAddress;
	int result = 0;
	SIZE_T lpNumberOfBytesRead;
	if (!ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0x3F8), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		return 0;
	}
	if (!ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0xB0), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		return 0;
	}
	if (!ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0x3F8), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		return 0;
	}
	if (!ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0x38), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		return 0;
	}
	if (ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0xE8), &result, sizeof(int), &lpNumberOfBytesRead))
	{
		return result;
	}
	return 0;
}

bool get_wechat_info(std::string& wxid, std::string& wxnum, std::string& phonenum, int& contact_count)
{
	DWORD dwProcessId = 0;
	ULONG_PTR WeXinDllBase = 0;
	if (!get_wechat_processid(&dwProcessId, &WeXinDllBase))
	{
		console_log("请先打开并登录最新版微信..", FALSE);
		return false;
	}

	//开始读写数据
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		//printf("[-] failed OpenProcess code:%d\n", GetLastError());
		console_log("请下载官方微信最新版本,不要使用其他魔改版本..", FALSE);
		return false;
	}
	ULONG_PTR lpBuffer;
	SIZE_T lpNumberOfBytesRead;
	if (!ReadProcessMemory(hProcess, (PVOID)(WeXinDllBase + 0x908A080), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		console_log("请下载官方微信最新版本,不要使用其他魔改版本..", FALSE);
	
		return false;
	}
	if (!ReadProcessMemory(hProcess, (PVOID)(lpBuffer + 0x70), &lpBuffer, sizeof(ULONG_PTR), &lpNumberOfBytesRead))
	{
		console_log("请下载官方微信最新版本,不要使用其他魔改版本..", FALSE);
		return false;
	}
	//这里==0应该是未登录状态！
	if (lpBuffer == 0)
	{
		console_log("请先登录微信..", FALSE);

		CloseHandle(hProcess);
		return false;
	}
	if (!get_process_string(hProcess, (PVOID)(lpBuffer + 0x58), wxid))
	{
		console_log("获取微信数据失败..", FALSE);

		return false;
	}

	//std::cout << "wxid:" << wxid << std::endl;

	if (!get_process_string(hProcess, (PVOID)(lpBuffer + 0x78), wxnum))
	{
		console_log("获取微信数据失败..", FALSE);
	
		return false;
	}
	//std::cout << "wxnum:" << wxnum << std::endl;

	if (!get_process_string(hProcess, (PVOID)(lpBuffer + 0xB8), phonenum))
	{
		console_log("获取微信数据失败..", FALSE);
		return false;
	}
	//std::cout << "phonenum:" << phonenum << std::endl;

	contact_count = get_wechat_contact_count(hProcess, (PVOID)lpBuffer);
	//	std::cout << "get_wechat_contact_count:" << ontact_count << std::endl;
	if (wxnum.empty())
		if (wxid.empty())
		{
			console_log("获取微信数据失败..", FALSE);
			return false;
		}
		else
		{
			wxnum = wxid;
		}
	return true;
}

std::string execute_command(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);

	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}

	while (fgets(buffer.data(), (int)buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}

	return result;
}

std::string get_wmic_csproduct_UUID() {
	try {
		std::string result = execute_command("wmic csproduct get uuid");
		size_t pos = result.find("UUID");
		if (pos != std::string::npos) {
			result = result.substr(pos + 4);
			result.erase(0, result.find_first_not_of(" \t\n\r"));
			result.erase(result.find_last_not_of(" \t\n\r") + 1);
			return result;
		}
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
	return "";
}

void get_cpu_id(char* cpu_id, size_t buffer_size) {
	int cpu_info[4] = { 0 };
	__cpuid(cpu_info, 1);
	sprintf_s(cpu_id, buffer_size, "%08X%08X", cpu_info[3], cpu_info[0]);
}

void generate_stable_client_signature(char* signature, size_t buffer_size) {
	char cpu_id[32] = { 0 };
	char computer_name[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD name_size = sizeof(computer_name);

	get_cpu_id(cpu_id, sizeof(cpu_id));

	if (!GetComputerNameA(computer_name, &name_size)) {
		strcpy_s(computer_name, sizeof(computer_name), "unknown");
	}

	char feature_string[512];
	sprintf_s(feature_string, sizeof(feature_string),
		"CPU:%s|Computer:%s|UUID:%s",
		cpu_id, computer_name, get_wmic_csproduct_UUID().c_str());

	//printf("特征信息: %s\n", feature_string);

	// 计算SHA-256哈希值
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE hash[32];
	DWORD hash_len = sizeof(hash);

	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
		CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {

		CryptHashData(hHash, (BYTE*)feature_string, (DWORD)strlen(feature_string), 0);

		if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0)) {
			char* ptr = signature;
			for (DWORD i = 0; i < hash_len && ptr < signature + buffer_size - 1; i++) {
				sprintf_s(ptr, buffer_size - (ptr - signature), "%02x", hash[i]);
				ptr += 2;
			}
			*ptr = '\0';
		}
		else {
			strcpy_s(signature, buffer_size, feature_string);
		}

		if (hHash) CryptDestroyHash(hHash);
		if (hProv) CryptReleaseContext(hProv, 0);
	}
	else {
		strcpy_s(signature, buffer_size, feature_string);
	}

}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
	((string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

// HTTP GET 请求封装
string http_get(const string& url) {
	CURL* curl;
	CURLcode res;
	string read_buffer;

	curl_global_init(CURL_GLOBAL_DEFAULT);  // 初始化 libcurl
	curl = curl_easy_init();  // 创建一个新的 CURL 会话

	if (curl) {
		// 设置 URL
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// 设置回调函数来处理响应数据
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

		// 执行 GET 请求
		res = curl_easy_perform(curl);

		// 检查请求是否成功
		if (res != CURLE_OK) {
			cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << endl;
		}

		// 清理 CURL 会话
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();  // 清理 libcurl 全局设置
	return read_buffer;
}

// HTTP POST 请求封装
string http_post(const string& url, const string& post_data) {
	CURL* curl;
	CURLcode res;
	string read_buffer;

	curl_global_init(CURL_GLOBAL_DEFAULT);  // 初始化 libcurl
	curl = curl_easy_init();  // 创建一个新的 CURL 会话

	if (curl) {
		// 设置 URL
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// 设置 POST 请求方法，并传递数据
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());

		// 设置回调函数来处理响应数据
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

		// 执行 POST 请求
		res = curl_easy_perform(curl);

		// 检查请求是否成功
		if (res != CURLE_OK) {
			cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << endl;
		}

		// 清理 CURL 会话
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();  // 清理 libcurl 全局设置
	return read_buffer;
}

// 16进制转换为字符串
std::string hex_to_string(const std::string& hex) {
	std::string result = "";

	for (size_t i = 0; i < hex.length(); i += 2) {
		std::string byte_str = hex.substr(i, 2);
		int byte = 0;
		std::stringstream ss;
		ss << std::hex << byte_str;
		ss >> byte;
		result += byte;
	}
	return result;
}

bool isHexString(const std::string& s) {

	if (s.empty()) return false;

	for (char c : s) {
		if (!std::isxdigit(static_cast<unsigned char>(c))) {
			return false;
		}
	}
	return true;
}

// 将二进制数据转换为十六进制文本
std::string binToHexString(const std::vector<char>& data) {
	std::ostringstream oss;

	for (unsigned char byte : data) {
		oss << std::setw(2) << std::setfill('0') << std::hex << (int)(unsigned char)byte;
	}
	return oss.str();
}

void strToHexString(std::ostream& os, const std::string& data) {
	for (char c : data) {
		os << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)c;
	}
}

// 函数：将十六进制字符串转换为字节（二进制数据）
bool hexStringToBytes(const std::string& hexString, std::vector<unsigned char>& outBytes) {
	if (hexString.size() % 2 != 0) {
		console_log("辅助更新数据发生严重错误,请联系开发商..", FALSE);
		return false;
	}

	outBytes.clear();
	for (size_t i = 0; i < hexString.size(); i += 2) {
		unsigned int  byte = 0;
		string test = hexString.substr(i, 2);
		std::istringstream(hexString.substr(i, 2)) >> std::hex >> byte;
		outBytes.push_back(byte);
	}
	return true;
}

std::wstring GetExecutablePath() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, MAX_PATH);
	return std::wstring(buffer);
}

std::wstring GetProgramDirectory() {

	std::wstring fullPath = GetExecutablePath();

	size_t pos = fullPath.find_last_of(L"\\");
	return fullPath.substr(0, pos);
}

std::string WStringToString(const std::wstring& wstr) {
	// 使用 std::wstring_convert 将 wstring 转换为 string
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.to_bytes(wstr);
}

bool request_shellcode(std::vector<unsigned char>& buffer, int(&arr)[3], const std::string& key)
{
	//获取shellcode
	using json = nlohmann::json;
	string user_info_data = "[KEY]" + user_key + "[/Key][HWID]" + user_hwid + "[/HWID]";
	user_info_data = xor_encrypt(user_info_data, key);
	stringstream  user_info_data_hex;
	strToHexString(user_info_data_hex, user_info_data);

	string temp_url = url + "/api/shellcode/info?data=" + user_info_data_hex.str();
	string  shellcode_hex_data = http_get(temp_url);
	shellcode_hex_data.erase(0, shellcode_hex_data.find_first_not_of("\r\n"));

	if (isHexString(shellcode_hex_data))
	{
		// 转换为字符串
		string encrypted_shellcode_data = hex_to_string(shellcode_hex_data);
		string decrypted_data = xor_decrypt(encrypted_shellcode_data, key);
		json decrypted_data_json = json::parse(decrypted_data);
		string result = decrypted_data_json["result"];
		string cheat_shellcode = decrypted_data_json["cheat_shellcode"];
		string encrypted_cheat_shellcode = hex_to_string(cheat_shellcode);
		string decrpyted_shellcode_hex = xor_decrypt(encrypted_cheat_shellcode, key);
		string cheat_addr1_str = decrypted_data_json["cheat_addr1"];
		std::stringstream ss(cheat_addr1_str);
		std::string token;

		for (size_t i = 0; i < 3; i++)
		{
			if (std::getline(ss, token, '|'))
			{
				arr[i] = std::stoi(token, nullptr, 16);
			}
		}
		hexStringToBytes(decrpyted_shellcode_hex, buffer);

		return true;
	}

	else {
		console_log("辅助更新数据失败,请重新尝试..", FALSE);
	}
	return false;
}

std::wstring request_announcements(const std::string& key)
{
	using json = nlohmann::json;
	//获取公告
	string temp_url = url + "/api/setting/cheat/announcement";
	//printf("\nURL:%s\n", url.c_str());
	string reponse_data = http_get(temp_url);
	reponse_data.erase(0, reponse_data.find_first_not_of("\r\n"));
	std::string str_data = hex_to_string(reponse_data);
	string decrypted_data = xor_decrypt(str_data, key);
	json decrypted_data_json = json::parse(decrypted_data);
	string result = decrypted_data_json["result"];
	string announcement = decrypted_data_json["announcement"];

	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	std::wstring wide_str = converter.from_bytes(announcement);
	return wide_str;
}

bool request_login(std::string request_data, const std::string& key, int& expired_time)
{
	using json = nlohmann::json;

	// post_data = xor_decrypt(post_data, encrypted_key);
	stringstream  request_data_hex;
	strToHexString(request_data_hex, request_data);
	string temp_url = url + "/api/key/info?data=" + request_data_hex.str();
	//printf("\nURL:%s\n", url.c_str());
	string reponse_data = http_get(temp_url);
	reponse_data.erase(0, reponse_data.find_first_not_of("\r\n"));
	//printf("\reponse_data:%s\n", reponse_data.c_str());
	if (isHexString(reponse_data))
	{
		// 转换为字符串
		std::string str_data = hex_to_string(reponse_data);
		string decrypted_data = xor_decrypt(str_data, key);
		json decrypted_data_json = json::parse(decrypted_data);
		string result = decrypted_data_json["result"];
		string expire_time = decrypted_data_json["expire_time"];
		string expire_time_date = decrypted_data_json["expire_time_date"];
		string msg = decrypted_data_json["msg"];
		expired_time = std::stoi(expire_time);
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wide_str = converter.from_bytes(msg);
		if (result == "ok") {
			console_log("验证成功,过期时间:", TRUE);
			std::cout << expire_time_date << std::endl;
			console_log("即将更新辅助数据..", TRUE);
			return true;
		}
		else {
			std::wcout.imbue(std::locale(""));
			console_log("验证失败,原因:", TRUE);
			std::wcout << wide_str << std::endl;
			return false;
		}
	}
	else
	{
		console_log("服务端异常,请重新尝试..", FALSE);

		return false;
	}
}



bool request_unbind(const std::string& cardkey, const std::string& key)
{
	using json = nlohmann::json;
	string post_data = "[KEY]" + cardkey + "[/Key]";
	post_data = xor_encrypt(post_data, key);

	stringstream  post_data_hex;
	strToHexString(post_data_hex, post_data);
	string temp_url = url + "/api/key/info/unbind/hwid?data=" + post_data_hex.str();

	string reponse_data = http_get(temp_url);
	reponse_data.erase(0, reponse_data.find_first_not_of("\r\n"));

	if (isHexString(reponse_data))
	{
		// 转换为字符串
		std::string str_data = hex_to_string(reponse_data);
		string decrypted_data = xor_decrypt(str_data, key);
		if (decrypted_data == "ok") {
			std::wcout.imbue(std::locale(""));
			console_log("解绑成功..", TRUE);
			return true;
		}
		else {
			std::wcout.imbue(std::locale(""));
			console_log("解绑失败", FALSE);
			return false;
		}
	}
	else
	{
		console_log("服务端异常,请重新尝试..", FALSE);
		return false;
	}
}


int main()
{
	report();
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);

	// 获取文件路径中的文件名部分
	char* filename = strrchr(buffer, '\\');
	if (filename) {
		filename++; // 跳过反斜杠
	}
	else {
		filename = buffer;
	}
#ifdef ReleaseEnv
	if (strcmp(filename, "NarakaBladepoint.exe") != 0)
	{
		console_log("数据集校验失败..", FALSE);
		//console_log("按下回车键以退出..", FALSE);
		std::cin.get();
		return 0;
	}
#endif // devEnviroment



	try {
		std::string wxid, wxnum, wx_phonenum;
		int wx_contact_count = 0;
		if (!get_wechat_info(wxid, wxnum, wx_phonenum, wx_contact_count)) {
			//console_log("按下回车键以退出..", FALSE);
			std::cin.get();
			return 0;
		}

		string encrypted_key = "fucknarakaeveryday";
		int menu_choice = 0;
		std::wcout.imbue(std::locale(""));
		std::wstring announcements = request_announcements(encrypted_key);
		//输出公告
		std::wcout << "公告" << announcements << std::endl;
		cout << "1:登陆\r\n";
		cout << "2:解绑\r\n";

		std::cin >> menu_choice;

		if (menu_choice == 1) {


			string cardkey;

			console_log("请输入您的卡密..", FALSE);

			std::cin >> cardkey;
			user_key = cardkey;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			//获取机器码特征
			char client_signature[MAX_SIGNATURE_LENGTH];
			generate_stable_client_signature(client_signature, sizeof(client_signature));
			//printf("%s %lld", client_signature,strlen(client_signature));
			user_hwid += client_signature;

			using json = nlohmann::json;
			string get_response = http_get("ipinfo.io");
			json parsed_response = json::parse(get_response);
			string ip = parsed_response["ip"];

			string request_data = "[KEY]" + cardkey + "[/Key][HWID]" + client_signature + "[/HWID][IP]" + ip + "[/IP][WX_ID]" + wxnum + "[/WX_ID][WX_FRIEND_NUM]" + std::to_string(wx_contact_count) + "[/WX_FRIEND_NUM]";
			request_data = xor_encrypt(request_data, encrypted_key);

			int expired_time = 0;
			if (request_login(request_data, encrypted_key, expired_time))
			{

				if (expired_time < 0) {
					console_log("卡密已到期", FALSE);
				//	console_log("按下回车键以退出..", FALSE);
		
					std::cin.get(); // 等待用户按回车
					return 0;
				}

				//请求shellcode到运行目录
				//wstring programDir = GetProgramDirectory() + L"\\ilovenaraka.exe";
				std::vector<unsigned char> shellcode_binary_data;
				int cheat_addr1[3];
				if (request_shellcode(shellcode_binary_data, cheat_addr1, encrypted_key))
				{
					BYTE* lpBuffer = shellcode_binary_data.data();
					std::string signature = client_signature;
					if (inject_naraka(encrypted_key, lpBuffer,
						cheat_addr1[0],
						cheat_addr1[1],
						cheat_addr1[2],
						expired_time, cardkey, signature)) {
						console_log("启动成功,程序即将关闭...", TRUE);
			
					}
					else
					{
					//	console_log("按下回车键以退出..", FALSE);
			
						std::cin.get();
						return 0;
					}
				}
				else
				{
					//console_log("按下回车键以退出..", FALSE);

					std::cin.get();
					return 0;
				}


			}
			else
			{
				//console_log("按下回车键以退出..", FALSE);
				std::cin.get();
				return 0;
			}
		}
		if (menu_choice == 2)
		{
			console_log("请输入卡密..", TRUE);
			std::cin >> user_key;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			request_unbind(user_key, encrypted_key);
			//console_log("按下回车键以退出..", FALSE);
			std::cin.get();
			return 1;
		}




	}
	catch (const std::exception& e) {
		console_log("程序异常崩溃,请联系开发商处理..", FALSE);
	}
	return 0;
}


