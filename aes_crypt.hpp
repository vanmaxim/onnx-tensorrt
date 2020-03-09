#pragma once

#include <cinttypes>
#include <vector>
namespace util
{
namespace crypt
{

bool aes_encrypt_256(std::vector<uint8_t> const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key);
bool aes_decrypt_256(struct EncryptedData const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key);

} // namespace crypt
} // namespace util
