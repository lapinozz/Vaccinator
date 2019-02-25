#pragma once

template <typename FunctionType>
class FunctionHook
{
public:
	FunctionHook(const std::string& targetName) : targetName(targetName)
	{
	}

	void init(void* hookFunction)
	{
		targetFunction = reinterpret_cast<void*>(GetProcAddress(GetModuleHandle(L"kernel32"), targetName.c_str()));
		if (!targetFunction)
		{
			targetFunction = reinterpret_cast<void*>(GetProcAddress(GetModuleHandle(L"ntdll"), targetName.c_str()));
		}

		shellcode = generateShellcode(reinterpret_cast<uintptr_t>(hookFunction));

		DWORD old_protect;
		VirtualProtect(targetFunction, 0x1000, 0x40, &old_protect);
		memcpy(originalCode.data(), targetFunction, originalCode.size());
		VirtualProtect(targetFunction, 0x1000, old_protect, &old_protect);

		hook();
	}

	void hook()
	{
		DWORD old_protect;
		VirtualProtect(targetFunction, 0x1000, 0x40, &old_protect);
		memcpy(targetFunction, shellcode.data(), shellcode.size());
		VirtualProtect(targetFunction, 0x1000, old_protect, &old_protect);
	}

	void unhook()
	{
		DWORD old_protect;
		VirtualProtect(targetFunction, 0x1000, 0x40, &old_protect);
		memcpy(targetFunction, originalCode.data(), originalCode.size());
		VirtualProtect(targetFunction, 0x1000, old_protect, &old_protect);
	}

	template <typename...Args>
	auto callOriginal(Args&&...args)
	{
		unhook();
		auto result = reinterpret_cast<FunctionType>(targetFunction)(std::forward<Args>(args)...);
		hook();

		return result;
	}

private:
	using RawCode = std::array<uint8_t, 0xF>;

	static RawCode generateShellcode(uintptr_t hook_pointer)
	{
		std::array<uint8_t, 0xF> hook_bytes = {
			0xFF, 0x35, 0x01, 0x00, 0x00, 0x00,							// PUSH [RIP+1]
			0xC3,														// RET
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };			// HOOK POINTER
		std::memcpy(hook_bytes.data() + 0x7, &hook_pointer, sizeof(hook_pointer));

		return hook_bytes;
	}

	void* targetFunction;
	std::string targetName;
	RawCode originalCode;
	RawCode shellcode;
};


/*
FunctionHook<decltype(&NtOpenFile)> NtOpenFileHook("NtOpenFile");
NTSTATUS NtOpenFileFunc(PHANDLE file_handle, ACCESS_MASK desired_access, POBJECT_ATTRIBUTES object_attributes, PIO_STATUS_BLOCK io_status_block, ULONG share_access, ULONG open_options)
{
	if (!isDisabled() && object_attributes && object_attributes->ObjectName)
	{
		if (std::wstring(object_attributes->ObjectName->Buffer).find(L"ducky") != std::wstring::npos)
		{
			return STATUS_NOT_FOUND;
		}
	}

	return NtOpenFileHook.callOriginal(file_handle, desired_access, object_attributes, io_status_block, share_access, open_options);
}

NtOpenFileHook.init(&NtOpenFileFunc);
*/