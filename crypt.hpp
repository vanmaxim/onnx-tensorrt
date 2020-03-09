#pragma once

#include <array>
#include <cinttypes>
#include <vector>

namespace util
{
namespace crypt
{

struct EncryptedData
{
  uint32_t m_dataSize;          // real data size (without alignment)
  std::vector<uint8_t> m_data;  // aligned data
};

bool EncryptData(std::vector<uint8_t> const & inputData, EncryptedData & outputData, std::vector<uint8_t> const & key);

bool EncryptToMemory(void const * inputData, std::size_t inputSize, std::vector<char> & outputData, std::string const & key);

bool DecryptFromMemory(std::vector<char> const & inputData, std::vector<char> & outputData, std::string const & key);

} // namespace crypt
} // namespace util
