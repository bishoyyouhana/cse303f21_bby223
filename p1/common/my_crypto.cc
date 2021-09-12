#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

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
  cout << "my_crypto.cc::aes_crypt_msg() is not implemented\n";

  //intialize characters
  //int c_len = *count + AES_BLOCKSIZE, f_len = 0;
  //unsigned char *ciphertext = malloc(c_len);
  //EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);

  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
  unsigned char out_buf[AES_BLOCKSIZE + cipher_block_size];
  int out_len;

  // crypt in_buf into out_buf
    if (!EVP_CipherUpdate(ctx, out_buf, &out_len, start, start.size())) {
      fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
              ERR_error_string(ERR_get_error(), nullptr));
      return {};
    }

    fwrite(out_buf, sizeof(unsigned char), out_len, out);
    if (ferror(out)) {
      perror("Error in fwrite()");
      return {};
    }

    // stop on EOF
    if (start.size() < AES_BLOCKSIZE) {
      break;
    }

      // The final block needs special attention!
    if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
      fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
      return {};
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, out);
    if (ferror(out)) {
      perror("Error in fwrite");
      return {};
    }
    vector<uint8_t> result = out_buf;
    return result;



  // These asserts are just for preventing compiler warnings:
  assert(ctx);
  assert(start);
  assert(count != -100);

  return {};
}
