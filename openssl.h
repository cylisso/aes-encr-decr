#pragma once
#include <string>
#include <vector>

namespace ssl
{
	std::vector<uint8_t> sha256(const std::string& str);

	void encrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::vector<uint8_t>& key);
	void decrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::vector<uint8_t>& key);

	std::vector<uint8_t> encrypt_bin(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
	std::vector<uint8_t> decrypt_bin(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
}