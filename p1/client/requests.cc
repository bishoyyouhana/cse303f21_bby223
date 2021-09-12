#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"

using namespace std;

/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  cout << "requests.cc::req_key() is not implemented\n";
  // send request for key
  // make sure key is of kblock length 
  std::vector<uint8_t> sendKey = REQ_KEY;
  while (sendKey.length() < LEN_RKBLOCK) { // add pad0 to end of vector
    sendKey.push_back('\0'); // append a null character
  }
  if (send_reliably(sd, sendKey)) { // key request sent
      std::vector<uint8_t> key = reliable_get_to_eof();
      while (key.empty()) { // keep reading until response is found
        key = reliable_get_to_eof();
      }
      if (keyfile.length == LEN_RSA_PUBKEY) { // make sure we get correct public key length
        write_file(keyfile, key, 0); // write to keyfile
      }
  }
  // NB: These asserts are to prevent compiler warnings (send reliable)
  assert(sd);
  assert(keyfile.length() > 0);
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  auto res = send_cmd(sd, pubkey, REQ_REG, ablock_ss(user, pass));
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  auto res = send_cmd(sd, pubkey, REQ_BYE, ablock_ss(user, pass));
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  auto res = send_cmd(sd, pubkey, REQ_SAV, ablock_ss(user, pass));
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  auto res = send_cmd(sd, pubkey, REQ_SET, ablock_sss(user, pass, setfile));
  send_result_to_file(res, setfile + ".file.dat");
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(setfile.length() > 0);
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  cout << "requests.cc::req_get() is not implemented\n";
  std::vector<uint8_t> msg = send_cmd(sd, pubkey, REQ_GET, ablock_sss(user, pass, getname));
  send_result_to_file(res, getname + ".file.dat");
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(getname.length() > 0);
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  cout << "requests.cc::req_all() is not implemented\n";
  std::vector<uint8_t> msg = send_cmd(sd, pubkey, REQ_ALL, ablock_sss(user, pass, allfile));
  send_result_to_file(res, allfile + ".file.dat");
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);
}


// helper functions
/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(vec &v, size_t sz) {
  int num = sz-v.size;
  unsigned char *buf;
  int bytes = RAND_bytes(buf, num);
  v.push_back(buf);
  return bytes;
}

/// Create unencrypted ablock contents from two strings
///
/// @param s1 The first string
/// @param s2 The second string
///
/// @return A vec representing the two strings
vec ablock_ss(const string &s1, const string &s2) {
  std::vector<uint8_t> result;
  // protocol.h s1 = user s2 = pass
  if (s1.size() > LEN_UNAME || s2.size() > LEN_PASSWORD) 
    return result;
  result.push_back(s1.size());
  result.push_back(s2.size());
  result.push_back(NULL);
  result.push_back(NULL);
  result.push_back(s1);
  result.push_back(s2);
  return result;
}

/// Create unencrypted ablock contents from two strings
///
/// @param s1 The first string
/// @param s2 The second string
/// @param s3 The third string
///
/// @return A vec representing the two strings
vec ablock_sss(const string &s1, const string &s2, const string &s3) {
  std::vector<uint8_t> result;
  if (s1.size() > LEN_UNAME || s2.size() > LEN_PASSWORD || s3.size() > LEN_PROFILE_FILE) 
    return result;
  result.push_back(s1.size());
  result.push_back(s2.size());
  result.push_back(s3.size());
  result.push_back(NULL);
  result.push_back(s1);
  result.push_back(s2);
  result.push_back(s3);
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err_crypto(const vec &v) {
  std::string str(vec.begin(), vec.end());
  if (strncpy(str, RES_ERR_CRYPTO, 2) == 0) {
    return true;
  }
  return false;
}

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vec send_cmd(int sd, RSA *pub, const string &cmd, const vec &msg) {
  std::vector<uint8_t> msgLen = msg.size;
  rBlock.resize(LEN_RKBLOCK);

  // build aBlock and encrypt
  std::vector<uint8_t> key = create_aes_key();
  EVP_CIPHER_CTX *aeskey = create_aes_context(key, true);
  std::vector<uint8_t> aBlockEncrypt = aes_crypt_msg(aeskey, msg);

  // build rBlock
  std::vector<uint8_t> rBlock = cmd;
  rBlock.push_back(aeskey);
  rBlock.push_back(msgLen);
  padR(rBlock);
  // encrypt rBlock
  std::vector<uint8_t> rBlockEncrypt(LEN_RKBLOCK);
  int numBytes = RSA_public_encrypt(LEN_RKBLOCK, rBlock.data, rBlockEncrypt.data, pubkey, RSA_PKCS1_OAEP_PADDING); 
  rBlockEncrypt.resize(numBytes);
  // check if encryption happend and send result
  if (aBlockEncrypt.size > 0 && rBlockEncrypt.size > 0) {
    std::vector<uint8_t> result;
    result.push_back(rBlockEncrypt);
    result.push_back(aBlockEncrypt);
    // send to server
    if(send_reliably(sd,result)) {
      std::vector<uint8_t> response = reliable_get_to_eof();
      while (response.empty()) { // keep reading until response is found
        response = reliable_get_to_eof();
      }

      // Check errors for decryption
      if (check_err_cryptol(response)) {
        cout << "Server could not decrypt @ablock"
        cout << endl;
        return std::vector<uint8_t> empty;
      }
      // decipher
      aeskey = reset_aes_context(key, false);
      std::vector<uint8_t> decrpytmsg = aes_crypt_msg(aeskey, response);
      reclaim_aes_context(aeskey);

      // error codes
      std::string str(decrpytmsg.begin(), decryptmsg.end());
      if (strncmp(msg, RES_OK, 2)) 
        cout << "Successful execution\n";
      else if (strncmp(msg, RES_ERR_LOGIN, 2)) {
        cout << "Not a valid user\n";
      }
      else if (strncmp(msg, RES_ERR_LOGIN, 2)) {
         cout << "Wrong password or user"
      }
      else if (strncmp(msg, RES_ERR_USER_EXISTS, 2)) {
        cout << "User already exists\n";
      }
      else if (strncmp(msg, RES_ERR_REQ_FMT, 2)) {
        cout << "Server unable to extract user or password from request\n";
      }
      else if (strncmp(msg, RES_ERR_NO_USER, 2)) {
        cout << "Not a valid user\n";
      }
      else if (strncmp(msg, RES_ERR_NO_DATA , 2)) {
        cout << "No data found on user\n";
      }
      else if (strncmp(msg, RES_ERR_SERVER, 2)) {
        cout << "Error on server side\n";
      }

      // return decrpytmsg
      return decrpytmsg;
    }
    else
      return std::vector<uint8_t> empty;
  }
  else 
    return std::vector<uint8_t> empty;
}

/// If a buffer consists of OKbbbbd+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vec &buf, const string &filename);