#include <winsock2.h>
#include <cstdio>
#include <windows.h>
#include <TlHelp32.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
using namespace std;
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

void compareFiles()
{
	ifstream file1("remoteip.txt");
	ifstream file2("malicious_ip.txt");
	ofstream file3("matched_ip.txt",ios::app);
	string line1, line2;
	int lineNum = 1;
	vector<string> ipAddresses;

	while (getline(file1, line1))
	{
		ipAddresses.push_back(line1);
	}
	while (getline(file2, line2))
	{
		if (find(ipAddresses.begin(), ipAddresses.end(), line2) != ipAddresses.end())
		{
			file3 << "Matched value in remoteip.txt:" << line2 << endl;
		}
	}
	
	file1.close();
	file2.close();
	file3.close();

}

void ip_check(char* remoteipaddress)
{
	ofstream MyFile("remoteip.txt", ios::app);

	if (MyFile.is_open())
	{

		MyFile << remoteipaddress << endl;
		MyFile.close();

	}



}

void PrintProcessIPAddresses(DWORD processid)
{
	PMIB_TCPTABLE2 tcpTable;
	DWORD tcpTableSize = 0;

	//get the size of tcp table
	if (GetTcpTable2(NULL, &tcpTableSize, TRUE) == ERROR_INSUFFICIENT_BUFFER)
	{
		tcpTable = (PMIB_TCPTABLE2)malloc(tcpTableSize);

		//retrieve tcp table 
		if (GetTcpTable2(tcpTable, &tcpTableSize, TRUE) == NO_ERROR)
		{
			printf("IP addresses connected to process with ID % lu:\n", processid);
			for (DWORD i = 0; i < tcpTable->dwNumEntries; i++)
			{
				MIB_TCPROW2 tcpRow = tcpTable->table[i];
				if (tcpRow.dwOwningPid == processid)
				{
					char localAddress[16];
					char remoteAddress[16];

					//convert local address to string
					inet_ntop(AF_INET, &(tcpRow.dwLocalAddr), localAddress, sizeof(localAddress));
					//convert remote address to string
					inet_ntop(AF_INET, &(tcpRow.dwRemoteAddr), remoteAddress, sizeof(remoteAddress));

					printf("Local Address: %s:%u\n", localAddress, ntohs((u_short)tcpRow.dwLocalPort));
					printf("Remote Address: %s:%u\n", remoteAddress, ntohs((u_short)tcpRow.dwRemoteAddr));
					printf("\n-------------------------------------------\n");
					ip_check(remoteAddress);

				}

			}
		}
		free(tcpTable);
	}

}



int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s <process_name>\n", argv[0]);
		return 1;
	}
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup failed\n");
		return 1;
	}
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	WCHAR prc[512];

	MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, prc, sizeof(prc) / sizeof(WCHAR));
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		do
		{
			if (wcscmp(entry.szExeFile, prc) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				if (hProcess == NULL)
				{
					printf("OpenProcess Error");
				}
				else
				{
					PrintProcessIPAddresses(entry.th32ProcessID);

				}
				CloseHandle(hProcess);
			}
		} while (Process32Next(snapshot, &entry));
	}
	CloseHandle(snapshot);
	compareFiles();
}
