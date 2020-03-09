#include "aes_crypt.hpp"
#include "crypt.hpp"

#include <mbedtls/aes.h>

#include <assert.h>

#include <cstring>
#include <vector>

namespace util
{
namespace crypt
{

namespace impl
{

size_t constexpr kAESBlockSize = 16;
int constexpr kModule = 1 << 8;

std::vector<uint8_t> GenIV()
{
  int const seed = 267;
  int const rounds = 11;

  std::vector<uint8_t> iv(kAESBlockSize);
  auto generator = [](uint32_t rounds, int seed)
  {
    int value = (seed & int(0xFFFFFFFF)) % kModule;

    int constexpr constAdd = 7141128627 % kModule;
    int constexpr constMul = 3011561 % kModule;

    for (uint32_t i = 0; i < rounds; ++i)
    {
      // assume that kModule ^ 2 < MAX_INT
      value = (constAdd + constMul * value) % kModule;
    }

    return value;
  };

  for (size_t i = 0; i < iv.size(); ++i)
  {
    iv[i] = uint8_t(generator(rounds, int(seed + i)) % 255);
  }

  return iv;
}

struct AESContextGuard
{
  AESContextGuard() { mbedtls_aes_init(&m_ctx); }
  ~AESContextGuard() { mbedtls_aes_free(&m_ctx); }

  mbedtls_aes_context m_ctx;
};

size_t CalcAlignedSize(size_t size)
{
  size_t const blockTail = size % kAESBlockSize;
  return (blockTail == 0) ? size : (size + (kAESBlockSize - blockTail));
}

bool encrypt(std::vector<uint8_t> const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key, uint32_t bitsNum)
{
  impl::AESContextGuard ctx;

  if (mbedtls_aes_setkey_enc(&ctx.m_ctx, key, bitsNum) != 0)
    return false;

  outputData.resize(CalcAlignedSize(inputData.size()));

  // mbedtls receive 16 byte aligned input
  std::vector<uint8_t> tmp(outputData.size());
  memcpy(tmp.data(), inputData.data(), inputData.size());

  assert(outputData.size() % kAESBlockSize == 0);

  auto iv = GenIV();
  assert(iv.size() == kAESBlockSize);

  mbedtls_aes_crypt_cbc(&ctx.m_ctx,
                        MBEDTLS_AES_ENCRYPT,
                        tmp.size(),
                        iv.data(),
                        tmp.data(),
                        outputData.data());
  return true;
}

bool decrypt(EncryptedData const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key, uint32_t bitsNum)
{
  impl::AESContextGuard ctx;

  if (mbedtls_aes_setkey_dec(&ctx.m_ctx, key, bitsNum) != 0)
    return false;

  auto iv = GenIV();
  assert(iv.size() == kAESBlockSize);

  std::vector<uint8_t> unpacked(inputData.m_data.size());
  mbedtls_aes_crypt_cbc(&ctx.m_ctx,
                        MBEDTLS_AES_DECRYPT,
                        inputData.m_data.size(),
                        iv.data(),
                        inputData.m_data.data(),
                        unpacked.data());

  outputData.assign(unpacked.data(), unpacked.data() + inputData.m_dataSize);

  return true;
}

} // namespace impl

bool aes_encrypt_256(std::vector<uint8_t> const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key)
{
  return impl::encrypt(inputData, outputData, key, 256);
}

bool aes_decrypt_256(EncryptedData const & inputData, std::vector<uint8_t> & outputData, uint8_t const * key)
{
  return impl::decrypt(inputData, outputData, key, 256);
}

} // namespace crypt
} // namespace util
