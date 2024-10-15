#include "openssl.h"
#include "utils.h"

void main()
{
	std::string _key = "*dxM^q(0)x-$+VR?ZC:e7FSOvS76VpC:=2Lm#yJXVx(=3l1D=sJXmAYU(V";
	auto key = ssl::sha256(_key);

	std::vector<uint8_t> vec1(123);
	for (auto& b : vec1) b = ru8();

	{
		std::string str1 = "Dota 2 zxczxcqqqeqqe | 123";

		auto str2 = ssl::encrypt_bin(s2v(str1), key);
		auto str3 = v2s(ssl::decrypt_bin(str2, key));
		if (str1 == str3) printf("strs match\n");
	}

	{
		auto vec2 = ssl::encrypt_bin(vec1, key);
		auto vec3 = ssl::decrypt_bin(vec2, key);
		if (vec1 == vec3) printf("vecs match\n");
	}

	{
		std::wstring p1 = L"1.bin";
		std::wstring p2 = L"enc.bin";
		std::wstring p3 = L"dec.bin";

		ssl::encrypt_file(p1, p2, key);
		ssl::decrypt_file(p2, p3, key);
	}
}