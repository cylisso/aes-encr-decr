#include "aes.h"
#include "sha256.h"
#include "openssl.h"
#include "utils.h"
#include <fstream>

std::vector<uint8_t> random_iv()
{
	std::vector<uint8_t> iv;
	for (int i = 0; i < AES_BLOCK_SIZE; i++) iv.push_back(ru8());
	return iv;
}

void xor_mess(std::vector<uint8_t>& data)
{
	uint64_t xoRs[] = { 0xFCABFC, 0xAFBADF, 0xEAEBFA, 0xEFDBFA, 0xDFDDFA, 0xFEAFFB };
	for (size_t i = 0; i < 6; i++) for (size_t j = 0; j < data.size(); j++) data[j] ^= static_cast<uint8_t>(xoRs[i]);
}

std::vector<uint8_t> ssl::sha256(const std::string& str)
{
	sha256_context context;
	std::vector<uint8_t> digest(SHA256_LENGTH);

	sha256_starts(&context);
	sha256_update(&context, str.data(), str.size());
	sha256_finish(&context, digest.data());

	return digest;
}

void ssl::encrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::vector<uint8_t>& key)
{
	std::vector<uint8_t> iv = random_iv();

	std::ifstream input_file(ipath, std::ios::ate | std::ios::binary);
	if (!input_file) return;

	std::ofstream output_file(opath, std::ios::binary);
	if (!output_file) return;

	size_t input_size = input_file.tellg();
	input_file.seekg(0);

	size_t padding_size = (AES_BLOCK_SIZE - (input_size % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;

	uint8_t header_buf[AES_BLOCK_SIZE] = { 0 };
	memcpy(header_buf, "GOOGLE", 6);
	output_file.write(reinterpret_cast<const char*>(header_buf), 6);
	memset(header_buf, 0, AES_BLOCK_SIZE);

	std::vector<uint8_t> header(AES_BLOCK_SIZE + 1);
	header[0] = static_cast<uint8_t>(padding_size);
	std::copy(iv.begin(), iv.end(), header.begin() + 1);
	xor_mess(header);
	output_file.write(reinterpret_cast<const char*>(header.data()), header.size());

	AES_CTX ctx;
	AES_EncryptInit(&ctx, key.data(), iv.data());

	uint8_t block_buf[AES_BLOCK_SIZE] = { 0 };
	while (input_file.read(reinterpret_cast<char*>(block_buf), AES_BLOCK_SIZE) || input_file.gcount() > 0)
	{
		size_t bytes_read = input_file.gcount();

		if (bytes_read < AES_BLOCK_SIZE)
		{
			std::fill(block_buf + bytes_read, block_buf + AES_BLOCK_SIZE, ru8());
		}

		AES_Encrypt(&ctx, block_buf, block_buf);
		output_file.write(reinterpret_cast<const char*>(block_buf), AES_BLOCK_SIZE);
	}

	AES_CTX_Free(&ctx);
}

void ssl::decrypt_file(const std::wstring& ipath, const std::wstring& opath, const std::vector<uint8_t>& key)
{
	std::ifstream input_file(ipath, std::ios::binary);
	if (!input_file) return;

	uint8_t header_buf[6] = { 0 };
	input_file.read(reinterpret_cast<char*>(header_buf), sizeof(header_buf));
	if (std::string(reinterpret_cast<char*>(header_buf), 6) != "GOOGLE") return;

	std::vector<uint8_t> tmp(17);
	input_file.read(reinterpret_cast<char*>(tmp.data()), tmp.size());
	xor_mess(tmp);

	std::vector<uint8_t> iv(tmp.begin() + 1, tmp.begin() + 1 + AES_BLOCK_SIZE);
	size_t pad_size = static_cast<size_t>(tmp[0]);

	std::ofstream output_file(opath, std::ios::binary);
	uint8_t buf[AES_BLOCK_SIZE] = { 0 };

	AES_CTX ctx;
	AES_DecryptInit(&ctx, key.data(), iv.data());

	while (input_file)
	{
		input_file.read(reinterpret_cast<char*>(buf), AES_BLOCK_SIZE);
		size_t bytes_read = input_file.gcount();

		if (bytes_read > 0)
		{
			AES_Decrypt(&ctx, buf, buf);

			if (pad_size != 0)
			{
				size_t current_pos = input_file.tellg();
				input_file.seekg(0, std::ios::end);
				size_t end_pos = input_file.tellg();
				size_t bytes_remaining = end_pos - current_pos; // predict remaining bytes
				input_file.seekg(current_pos);

				if (bytes_remaining == 0)
				{
					output_file.write(reinterpret_cast<const char*>(buf), bytes_read - pad_size);
					break;
				}
			}

			output_file.write(reinterpret_cast<const char*>(buf), bytes_read);
		}
	}

	AES_CTX_Free(&ctx);
}

std::vector<uint8_t> ssl::encrypt_bin(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key)
{
	std::vector<uint8_t> iv = random_iv();
	size_t pad_size = (AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;

	std::vector<uint8_t> tmp_enc(data);
	tmp_enc.insert(tmp_enc.end(), pad_size, ru8());

	std::vector<uint8_t> enc_data(tmp_enc.size());

	AES_CTX ctx;
	AES_EncryptInit(&ctx, key.data(), iv.data());

	for (size_t i = 0; i < tmp_enc.size(); i += AES_BLOCK_SIZE)
	{
		AES_Encrypt(&ctx, tmp_enc.data() + i, enc_data.data() + i);
	}

	AES_CTX_Free(&ctx);

	std::vector<uint8_t> ret(1 + AES_BLOCK_SIZE + enc_data.size());
	ret[0] = static_cast<uint8_t>(pad_size);
	std::copy(iv.begin(), iv.end(), ret.begin() + 1);
	std::copy(enc_data.begin(), enc_data.end(), ret.begin() + 1 + AES_BLOCK_SIZE);

	xor_mess(ret);
	return ret;
}

std::vector<uint8_t> ssl::decrypt_bin(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key)
{
	if (data.size() < AES_BLOCK_SIZE + 2) {
		return {};
	}

	std::vector<uint8_t> _data = data;
	xor_mess(_data);

	size_t pad_size = _data[0];
	std::vector<uint8_t> iv(_data.begin() + 1, _data.begin() + 1 + AES_BLOCK_SIZE);
	std::vector<uint8_t> enc_data(_data.begin() + 1 + AES_BLOCK_SIZE, _data.end());
	std::vector<uint8_t> dec_data(enc_data.size());

	AES_CTX ctx;
	AES_DecryptInit(&ctx, key.data(), iv.data());

	for (size_t i = 0; i < enc_data.size(); i += AES_BLOCK_SIZE)
	{
		AES_Decrypt(&ctx, enc_data.data() + i, dec_data.data() + i);
	}

	AES_CTX_Free(&ctx);

	if (pad_size > 0 && pad_size <= AES_BLOCK_SIZE)
	{
		dec_data.resize(dec_data.size() - pad_size);
	}

	return dec_data;
}