#pragma once

#include <ostream>
#include <fstream>
#include <mutex>

class SafeLogger
{
public:
	SafeLogger(std::wostream& stream, std::mutex& mutex) : stream(stream), lock(mutex)
	{

	}

	SafeLogger(SafeLogger&&) = default;

	SafeLogger(const SafeLogger&) = delete;
	void operator=(SafeLogger&&) = delete;
	void operator=(const SafeLogger&) = delete;

	template <typename T>
	SafeLogger& operator<<(T&& t)
	{
		stream << std::forward<T>(t);
		return *this;
	}

	SafeLogger& operator<<(std::wostream& (*t)(std::wostream&))
	{
		t(stream);
		return *this;
	}

	static SafeLogger log()
	{
		static std::mutex mutex;
		static std::wofstream file("C:\\log.txt");

		return { file, mutex };
	}

private:

	std::wostream& stream;
	std::unique_lock<std::mutex> lock;
};
