# dll注入后通过socket与主程序通讯的例子  
上次有写了个通过内存共享实现进程间通信的例子。重新用sokcet写了一遍。   
Tcp/Ip socket用到这里好像有点大材小用，毕竟只有几次的通讯过程。但是也是个方法。   
主程序是VB.NET，当服务端，要注入的dll是c++，当客户端。   
dll源码，SocketClient.cpp：
```c
#include "pch.h"
#include<WINSOCK2.H>
#include<STDIO.H>
#include<iostream>
#include<cstring>
#include <WS2tcpip.h>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996) 

typedef struct func1
{
	char structHWID[64];
	unsigned char sizeHWID[4];
};
typedef struct func2
{
	BYTE pbData[32];
	int dwSize;
	BYTE pbDst[256];
	unsigned int sizeDst;
};
typedef struct func3
{
	char Src[1000];
	char pbData[1024];
	unsigned DataSize;
};
typedef struct AgrListStruct
{
	int FuncFlag;
	func1 f1;
	func2 f2;
	func3 f3;
};

AgrListStruct CallExe(AgrListStruct);
SOCKET sClient;

int startClient(const char* host, int port)
{
	AgrListStruct funcstruct;
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return 0;
	}
	
		sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sClient == INVALID_SOCKET)
		{
			printf("invalid socket!");
			return 0;
		}
		sockaddr_in serAddr;
		serAddr.sin_family = AF_INET;
		serAddr.sin_port = htons(port);
		serAddr.sin_addr.S_un.S_addr = inet_addr(host);
		if (connect(sClient, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{  
			printf("connect error !");
			closesocket(sClient);
			return 0;
		}
	while (true)
	{
		char recData[1024*4];
		memset(recData, 0, 1024 * 4);
		int ret = recv(sClient, recData, 1024 * 4, 0);
		if (ret > 0)
		{
			memset(&funcstruct, 0, sizeof(AgrListStruct));
			memcpy(&funcstruct, recData, sizeof(AgrListStruct));
			AgrListStruct funcstructs = CallExe(funcstruct);
		}

		char sendData[1024 * 4];
		memset(sendData, 0, 1024 * 4);
		memcpy(sendData, &funcstruct, sizeof(AgrListStruct));
		send(sClient, sendData, sizeof(sendData), 0);
		
	}	
	return 0;
}

void closeClient()
{
	closesocket(sClient);
	WSACleanup();
}
```
dllmain.cpp
```c
AgrListStruct CallExe(AgrListStruct funcstruct)
{   

    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandle(NULL);// GetModuleHandle(L"gatherosstate64.exe");
    if (hModule == 0)
        return funcstruct;
    if (funcstruct.FuncFlag == 2)
    {
        goto func2;
    }
    else if (funcstruct.FuncFlag == 3)
    {
        goto func3;
    }


func1:
    {
        BYTE ByteGetCurrentEx[] = "\x48\x8B\xC4\x4C\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x48\x89\x48\x08\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x48";
        char MaskGetCurrentEx[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        DWORD64 pHwidGetCurrentEx = FindPattern64(hModule, ByteGetCurrentEx, MaskGetCurrentEx);
        if (pHwidGetCurrentEx == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return funcstruct;
        }

        typedef int(__stdcall* DelegateHwidGetCurrentEx)(unsigned __int8*, unsigned int, int**, unsigned int*, int**, unsigned int*); //__cdecl
        DelegateHwidGetCurrentEx MyHwidGetCurrentEx = (DelegateHwidGetCurrentEx)(static_cast<long long>(pHwidGetCurrentEx));
        int* structHWID;
        unsigned int sizeHWID;

        int result = MyHwidGetCurrentEx(NULL, 0, &structHWID, &sizeHWID, 0, 0);
        if (result != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", result);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return funcstruct;
        }

        ::memcpy(funcstruct.f1.structHWID, structHWID, sizeof(funcstruct.f1.structHWID));
        ::memcpy(funcstruct.f1.sizeHWID, (unsigned char*)&sizeHWID, 4);
        return funcstruct;
    }

func2:
    {
        BYTE ByteVRSAVaultSignPKCS[] = "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x56\x41\x57\x48\x83\xEC\x20\x4C\x8B\x74\x24\x00\x4D\x8B\xF9\x49\x8B\xD8\x8B\xFA\x48\x8B\xE9\x45\x8B\x16\x41\x8D\x72\xFE\x41\x8D\x42\xFF\x42\xC6\x04\x00\x00";
        char MaskVRSAVaultSignPKCS[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxx?";
        DWORD64 pVRSAVaultSignPKCS = FindPattern64(hModule, ByteVRSAVaultSignPKCS, MaskVRSAVaultSignPKCS);
        if (pVRSAVaultSignPKCS == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return funcstruct;
        }

        typedef __int64(__fastcall* DelegateVRSAVaultSignPKCS)(const void*, int a2, int* a3, const unsigned int* a4, unsigned int* a5);
        DelegateVRSAVaultSignPKCS MyVRSAVaultSignPKCS = (DelegateVRSAVaultSignPKCS)pVRSAVaultSignPKCS;
        unsigned int callcount = 0x100;
        int pbDST[256] = { 0 };
        unsigned int SizeDST;

        DWORD64 result = MyVRSAVaultSignPKCS(funcstruct.f2.pbData, funcstruct.f2.dwSize, pbDST, &SizeDST, &callcount);
        if (result != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", (int)result);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return funcstruct;
        }
        ::memcpy(funcstruct.f2.pbDst, pbDST, 256);
        funcstruct.f2.sizeDst = SizeDST;
        return funcstruct;
    }

func3:
    {
        BYTE ByteCreateGenuineTicketClient[] = "\x48\x89\x5C\x24\x00\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x85\x00\x00\x00\x00\x45\x33\xFF\x4D\x8B\xE0\x4C\x8B\xF1\x4C\x89\x7D\x98";
        char MaskCreateGenuineTicketClient[] = "xxxx?xxxxxxxxxxxxxxx????xxx????xxx????xxxxxx????xxxxxxxxxxxxx";
        DWORD64 pCreateGenuineTicketClient = FindPattern64(hModule, ByteCreateGenuineTicketClient, MaskCreateGenuineTicketClient);
        if (pCreateGenuineTicketClient == 0)
        {
            LPSTR messageBuffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
            LocalFree(messageBuffer);
            return funcstruct;
        }

        typedef __int64(__fastcall* DelegateCreateGenuineTicketClient)(void* Src, __int64 a2, unsigned int* a3, unsigned __int8** a4);
        DelegateCreateGenuineTicketClient MyCreateGenuineTicketClient = (DelegateCreateGenuineTicketClient)pCreateGenuineTicketClient;
        unsigned int DataSize = 0;
        unsigned __int8* pbData;
        DWORD64 results = MyCreateGenuineTicketClient(funcstruct.f3.Src, 0xC004F012, &DataSize, &pbData);
        if (results != 0)
        {
            char buffer[32];
            sprintf_s(buffer, "%d", (int)results);
            MessageBoxA(NULL, buffer, "DllTitle", MB_ICONINFORMATION);
            return funcstruct;
        }
        ::memcpy(funcstruct.f3.pbData, pbData, sizeof(funcstruct.f3.pbData));
        funcstruct.f3.DataSize = DataSize;
        return funcstruct;
    }
    return funcstruct;
}

void __stdcall Connect()
{
    startClient("127.0.0.1", 8888);
}
void DisConnect()
{
    closeClient();
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Connect, NULL, 0, &dwThreadId);
        break;
    case DLL_THREAD_ATTACH:

    case DLL_THREAD_DETACH:
        
    case DLL_PROCESS_DETACH:
        DisConnect;
        break;
    }
    return TRUE;
}



```


