#pragma once
#include <windows.h>
#include <vector>
#include <string>

extern "C" void fnGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);

static uint64_t fnXtime_get_ticks()
{
	_FILETIME SystemTimeAsFileTime;
	fnGetSystemTimeAsFileTime(&SystemTimeAsFileTime);

	uint64_t a1 = static_cast<uint64_t>(SystemTimeAsFileTime.dwLowDateTime);
	uint64_t a2 = static_cast<uint64_t>(SystemTimeAsFileTime.dwHighDateTime);
	return (a1 + (a2 << 32)) - 116444736000000000llu;
}

template <typename T>
T randuint(T min, T max)
{
	if (min > max) return min;

	static uint64_t seed = fnXtime_get_ticks();

	for (int i = 1; i < 64; i++) {
		seed = i + 0x5851F42D4C957F2Dllu * ((seed >> 62) ^ seed);
	}

	uint64_t state = seed;
	for (int i = 0; i < 312; i++) {
		state = (state ^ (state >> 1)) & 0xFFFFFFFF80000000ull;
		state ^= (state >> 1) ^ 0xB5026F5AA96619E9ull;
	}

	uint64_t value = (state >> 29) ^ state;
	uint64_t p1 = (((((value & 0x38EB3FFFF6D3) << 17) ^ value) & 0xFFFFFFFFFFFFBF77) << 37);
	uint64_t rn = static_cast<uint64_t>(p1 ^ ((value & 0x38EB3FFFF6D3) << 17) ^ value) ^ (value >> 43);
	return min + static_cast<T>(rn % (static_cast<uint64_t>(max - (min + 1) + 1)));
}

inline uint8_t ru8()
{
	return randuint<uint8_t>(0, 0xFF);
}

inline std::string v2s(const std::vector<uint8_t>& vec) {
	return std::string(vec.begin(), vec.end());
}

inline std::vector<uint8_t> s2v(const std::string& str) {
	return std::vector<uint8_t>(str.begin(), str.end());
}