/************************************************************************
* Windows Network Event Coorelation
* Proof of Concept  
* @real_Slacker007 
* Module (1) : List Running Processes
************************************************************************/
//C++ Declarations
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include "/home/slacker007/Code/scripts/C_code/data.h"
//-------------------------


int PrintMods (DWORD pID)
{	HMODULE hMod[1024];
	DWORD cbNeeded;
	DWORD pPathBuf;
	unsigned int i, x = 1, y = 0;
	TCHAR pPath[MAX_PATH];
	ArrayData procArray[200][3];
	// = {{"Process ID"}, {"Address To Process Handle"}, {"Full Path to the Process"}};

	//Get a handle to the process
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID);
	
        //Print the process ID's <pID>
	_tprintf(TEXT("Process ID: %i \n"), pID);
	procArray[x][y] = &pID;
	_tprintf(TEXT("Address To Proc Handle:\t%08X\n"), hProcess);
	//procArray[x][++y] = hProcess;
	GetProcessImageFileName (hProcess, \
					pPath, \
					sizeof(pPath)/sizeof(*pPath));									

	_tprintf(TEXT("Full Path to the Process:\t%s\n"), pPath);
	//procArray[x][++y] = pPath;

	if (NULL == hProcess )
		return 1; 

	if (EnumProcessModules(hProcess, hMod, sizeof(hMod), &cbNeeded))
	{
		DWORD modCount;
		MODULEINFO modInfo;
                TCHAR szModName[MAX_PATH];
	
		// # of modules for each process
		modCount = cbNeeded / sizeof(HMODULE);		


		for (i=0; i<modCount; i++)
		{		
		
			// Get the full path to module file
			if (GetModuleFileNameEx(hProcess, hMod[i], szModName, sizeof(szModName) / sizeof(TCHAR)));
			{	
				//Print mod name & handle value
				_tprintf(TEXT("\tFull Path to Modules:\t%s \n"), szModName);
			}
			if (GetModuleBaseName(hProcess,hMod[i], szModName, sizeof(szModName) / sizeof(TCHAR)));
			{
				//Print mod Base Name 
				_tprintf(TEXT("\tModule Name:\t%s\n"), szModName);
			}
			if(GetModuleInformation(hProcess, hMod[i], &modInfo, sizeof(szModName) / sizeof(modInfo)));
			{
                                //Print MOD INFO
				_tprintf(TEXT("\t\t Module Base Address:\t%p\n"), modInfo.lpBaseOfDll);
				_tprintf(TEXT("\t\t Module Size        :\t%08X\n"), modInfo.SizeOfImage);
				_tprintf(TEXT("\t\t Module Entry Point :\t%p\n"), modInfo.EntryPoint);
				printf("\n");
			}
		}
	}
	CloseHandle(hProcess);
	return 0;
}

int main ( void )
{
        DWORD aProcesses[1024];
        DWORD cbNeeded;
        DWORD cProcesses;
	unsigned int i = 0;

	// Get the list of process identifiers
        if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        {
                return 1;
        }

// Calculate how many process identifiers were returned

        cProcesses = cbNeeded / sizeof (DWORD);

// Print the names of the  modules for each process


        for (i = 0; i < cProcesses; i++)
        {
                if(aProcesses[i] !=0)
                {
                        PrintMods(aProcesses[i]);
                }
        }

        return 0;
}

