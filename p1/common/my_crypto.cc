#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>
#include <cstring>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "err.h"

using namespace std;

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start,
                              int count) {
  //cout << "my_crypto.cc::aes_crypt_msg() is not implemented\n";

  //intialize characters
  //int c_len = *count + AES_BLOCKSIZE, f_len = 0;
  //unsigned char *ciphertext = malloc(c_len);
  //EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);

  // need to find amount of data to store in a buffer of characters to write into. 1 megabyte?
  // intialize variables, to use. This should include an out buffer, the length of that buffer read.
  // Then encrypt/ decrypt the start address in memory to the length of count.
  // Do one crypt count = message size, so all of the bytes in the message are crypted.
  // Error check cryption
  // If there are any other data un-caught by the update should be called by Final to catch the cipher block
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
  std::vector<uint8_t> out_buf(count + 2*cipher_block_size);
  int out_len, fl_len;

  // crypt in_buf into out_buf
    int a = EVP_CipherUpdate(ctx, out_buf.data(), &out_len, start, count);
    if (!a) {
      fprintf(stderr, "Error in EVP_CipherUpdate\n");
      return {};
    }

    // EVP_CipherUpdate(ctx, out_buf.data(), &out_len, NULL, 0);
    // The final block needs special attention!
    int b = EVP_CipherFinal_ex(ctx, out_buf.data() + out_len, &fl_len);
    if (!b) {
      fprintf(stderr, "Error in EVP_CipherFinal_ex\n");
      return {};
    } 
    // resize to get correct format :D
    out_buf.resize(out_len + fl_len);
    return out_buf;



  // These asserts are just for preventing compiler warnings:
  /*assert(ctx);
  assert(start);
  assert(count != -100);

  return {};
  */
}
