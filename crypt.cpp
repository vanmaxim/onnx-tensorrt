#include "aes_crypt.hpp"
#include "crypt.hpp"

#include <assert.h>
#include <cstring>
#include <map>

namespace util
{
namespace crypt
{

namespace impl
{

size_t constexpr kKeyLength = 32;

bool encryptAES_256(std::vector<uint8_t> const & input, std::vector<uint8_t> & output, std::vector<uint8_t> const & k)
{
  assert(k.size() == kKeyLength);
  return util::crypt::aes_encrypt_256(input, output, k.data());
}

bool decryptAES_256(EncryptedData const & input, std::vector<uint8_t> & output, std::vector<uint8_t> const & k)
{
  if (k.size() != kKeyLength)
    return false;

  return util::crypt::aes_decrypt_256(input, output, k.data());
}

} // namespace impl

bool EncryptData(std::vector<uint8_t> const & inputData, EncryptedData & outputData, std::vector<uint8_t> const & key)
{
  if (key.size() != impl::kKeyLength)
    return false;

  outputData.m_dataSize = uint32_t(inputData.size());
  return impl::encryptAES_256(inputData, outputData.m_data, key);
}

bool DecryptData(EncryptedData const & inputData, std::vector<uint8_t> & outputData, std::vector<uint8_t> const & key)
{
  assert(key.size() == impl::kKeyLength);
  return impl::decryptAES_256(inputData, outputData, key);
}

bool EncryptToMemory(void const * inputData, std::size_t inputSize, std::vector<char> & outputData, std::string const & key)
{
  std::vector<uint8_t> input(inputSize);
  std::memcpy(input.data(), inputData, inputSize);

  std::vector<uint8_t> const k(key.begin(), key.end());

  EncryptedData output;
  if (!EncryptData(input, output, k))
    return false;

  outputData.resize(sizeof(output.m_dataSize) + output.m_data.size());
  std::memcpy(outputData.data(), &output.m_dataSize, sizeof(output.m_dataSize));
  std::memcpy(outputData.data() + sizeof(output.m_dataSize), output.m_data.data(), output.m_data.size());

  return true;
}

bool DecryptFromMemory(std::vector<char> const & inputData, std::vector<char> & outputData, std::string const & key)
{  
  EncryptedData input;
  std::memcpy(&input.m_dataSize, inputData.data(), sizeof(input.m_dataSize));

  auto const dataBeginIt = inputData.begin() + sizeof(input.m_dataSize);  //or data()?
  input.m_data.assign(dataBeginIt, inputData.end());

  std::vector<uint8_t> uintOutputData;
  std::vector<uint8_t> const k(key.begin(), key.end());

  auto const isDecrypted = DecryptData(input, uintOutputData, k);

  outputData.assign(uintOutputData.begin(), uintOutputData.begin() + uintOutputData.size());
  return isDecrypted;
}

} // namespace crypt
} // namespace util
