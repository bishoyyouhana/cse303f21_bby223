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

// helper functions
/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(std::vector<uint8_t> &v, size_t sz) {
  int num = sz-v.size();
  unsigned char buf[num];
  int bytes = RAND_bytes(buf, num);
  for (int i = 0; i < (int) sizeof(buf); i++)
    v.push_back((uint8_t) buf[i]);
  if(bytes)
    return true;
  return false;
}

/// Create unencrypted ablock contents from two strings
///
/// @param s1 The first string
/// @param s2 The second string
///
/// @return A vec representing the two strings
std::vector<uint8_t> ablock_ss(const string &s1, const string &s2) {
  // check correct length, if not return nothing as error.
  if (s1.size() > LEN_UNAME || s2.size() > LEN_PASSWORD) 
    return {};
  // final vector we send/return.
  std::vector<uint8_t> result;
  // convert strings into uint_8 vectors
  std::vector<uint8_t> s1vector(s1.begin(), s1.end());
  std::vector<uint8_t> s2vector(s2.begin(), s2.end());
  
  size_t s1size = s1vector.size();
  size_t s2size = s2vector.size();
  //size_t s1size = s1.size();
  //size_t s2size = s2.size();
  // add length's of s1 and s2 to the front of vector
  result.insert(result.end(), (uint8_t*) &s1size, ((uint8_t*) &s1size) + sizeof(s1size));
  result.insert(result.end(), (uint8_t*) &s2size, ((uint8_t*) &s2size) + sizeof(s2size));
  // add null values into block
  for (int i = 0; i < 16; i++)
    result.push_back(0x00);
  
  
  // add string vectors to main result
  //https://www.includehelp.com/stl/appending-a-vector-to-a-vector.aspx#:~:text=To%20insert%2Fappend%20a%20vector%27s%20elements%20to,another%20vector%2C%20we%20use%20vector%3A%3Ainsert%20%28%29%20function.
  result.insert(result.end(), s1vector.begin(), s1vector.end());
  result.insert(result.end(), s2vector.begin(), s2vector.end());

  result.resize(32 + s1vector.size() + s2vector.size());

  return result;
}

/// Create unencrypted ablock contents from two strings
///
/// @param s1 The first string
/// @param s2 The second string
/// @param s3 The third string
///
/// @return A vec representing the two strings
std::vector<uint8_t> ablock_sss(const string &s1, const string &s2, const string &s3) {
  if (s1.size() > LEN_UNAME || s2.size() > LEN_PASSWORD || s3.size() > LEN_PROFILE_FILE) 
    return {};
  // final vector we send/return.
  std::vector<uint8_t> result;

   // convert strings into uint_8 vectors
  std::vector<uint8_t> s1vector(s1.begin(), s2.end());
  std::vector<uint8_t> s2vector(s2.begin(), s2.end());
  std::vector<uint8_t> s3vector(s3.begin(), s3.end());

  size_t s1size = s1vector.size();
  size_t s2size = s2vector.size();
  size_t s3size = s3vector.size();
  // add length's of s1 and s2 to the front of vector
  result.insert(result.end(), (uint8_t*) &s1size, ((uint8_t*) &s1size) + sizeof(s1size);
  result.insert(result.end(), (uint8_t*) &s2size, ((uint8_t*) &s2size) + sizeof(s2size);
  result.insert(result.end(), (uint8_t*) &s3size, ((uint8_t*) &s3size) + sizeof(s3size);
  // add null values into block
  for (int i = 0; i < 8; i++)
    result.push_back(0x00);
 
  // add string vectors to main result
  //https://www.includehelp.com/stl/appending-a-vector-to-a-vector.aspx#:~:text=To%20insert%2Fappend%20a%20vector%27s%20elements%20to,another%20vector%2C%20we%20use%20vector%3A%3Ainsert%20%28%29%20function.
  result.insert(result.end(), s1vector.begin(), s1vector.end());
  result.insert(result.end(), s2vector.begin(), s2vector.end());
  result.insert(result.end(), s3vector.begin(), s3vector.end());

  result.resize(32 + s1.size() + s2.size() + s3.size());

  return result;
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err_crypto(const std::vector<uint8_t> &v) {
  std::string str(v.begin(), v.end());
  if (str.compare(RES_ERR_CRYPTO) == 0) {
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
std::vector<uint8_t> send_cmd(int sd, RSA *pub, const string &cmd, const std::vector<uint8_t> &msg) {
  // build the key for the a block, pub key will be used for the rBlock
  // creates the aes key used for the request
  std::vector<uint8_t> key = create_aes_key();
  // key.resize(AES_KEYSIZE);

  // create the contex for the encryption
  EVP_CIPHER_CTX *aeskey = create_aes_context(key, true);
  std::vector<uint8_t> aBlockEncrypt = aes_crypt_msg(aeskey, msg);
  //aBlockEncrypt.resize(AES_BLOCKSIZE);

  // build rBlock from protocol.h, start with building the request string
  std::vector<uint8_t> rBlock(cmd.begin(), cmd.end());
  //rBlock.resize(LEN_RKBLOCK);
  // add aeskey into the unencrypted rBlock
  rBlock.insert(rBlock.end(), key.begin(), key.end());
  //size_t msgSize = msg.size();
  //rBlock.insert(rBlock.end(), (uint8_t*) &msgSize, ((uint8_t*) &msgSize)) + sizeof(msgSize));
  // add the unecrypted ablock length to rBlock
  size_t aBlockSize = aBlockEncrypt.size();
  rBlock.insert(rBlock.end(), (uint8_t*) &aBlockSize, ((uint8_t*) &aBlockSize) + sizeof(aBlockSize));

  // pad and resize for formatting
  if (!padR(rBlock, LEN_RBLOCK_CONTENT))
    return {};
  // rBlock.resize(LEN_RBLOCK_CONTENT);

  // encrypt rBlock using RSA encryption
  std::vector<uint8_t> rBlockEncrypt(RSA_size(pub));

  int numBytes = RSA_public_encrypt(rBlock.size(), rBlock.data(), rBlockEncrypt.data(), pub, RSA_PKCS1_OAEP_PADDING); 
  numBytes++;
  //rBlockEncrypt.resize(numBytes);
  // rBlockEncrypt.resize(LEN_RKBLOCK);

  // check if encryption happend and send result
  if (aBlockEncrypt.size() > 0 && rBlockEncrypt.size() > 0) {
    // create a single block to send to the server
    std::vector<uint8_t> result;
    result.insert(result.end(), rBlockEncrypt.begin(), rBlockEncrypt.end());
    result.insert(result.end(), aBlockEncrypt.begin(), aBlockEncrypt.end());
    // result.resize(rBlockEncrypt.size() + aBlockEncrypt.size()); 
    /*for (int i = 0; i < (int) rBlockEncrypt.size(); i++)
      result.push_back(rBlockEncrypt.at(i));
    for (int i = 0; i < (int) aBlockEncrypt.size(); i++)
      result.insert(result.end(), aBlockEncrypt.at(i)); */
    // send to server
    if(send_reliably(sd, result)) {
      //send_reliably(sd, aBlockEncrypt);
      std::vector<uint8_t> response = reliable_get_to_eof(sd);

      // Check errors for decryption by the client-side (told by server)
      if (check_err_crypto(response)) {
        cout << RES_ERR_CRYPTO;
        cout << endl;
        return {};
      }

      // decipher
      // reset the context to be used for decryption
      reset_aes_context(aeskey, key, false);
      std::vector<uint8_t> decrpytmsg = aes_crypt_msg(aeskey, response);
      // reclaim the memory the context use
      reclaim_aes_context(aeskey);

      // error codes
      std::string str(decrpytmsg.begin(), decrpytmsg.end()); // convert message into string for comparison
      if (str == RES_OK) { // Look for OK, means request went through to server
        //cout << "Successful execution";
        //cout << endl;
        return decrpytmsg;
      }
      else if (str == RES_ERR_LOGIN) { // error messages
        cout << RES_ERR_LOGIN;
        cout << endl;
      }
      else if (str == RES_ERR_LOGIN) {
        cout << RES_ERR_LOGIN;
        cout << endl;
      }
      else if (str == RES_ERR_USER_EXISTS) {
        cout << RES_ERR_USER_EXISTS;
        cout << endl;
      }
      else if (str == RES_ERR_REQ_FMT) {
        cout << RES_ERR_REQ_FMT;
        cout << endl;
      }
      else if (str == RES_ERR_NO_USER) {
        cout << RES_ERR_NO_USER;
        cout << endl;
      }
      else if (str == RES_ERR_NO_DATA) {
        cout << RES_ERR_NO_DATA;
        cout << endl;
      }
      else if (str == RES_ERR_SERVER) {
        cout << RES_ERR_SERVER;
        cout << endl;
      }

      // return empty, error or nothing was caught
      return {};
    }
    else
      return {};
  }
  else 
    return {};
}

/// If a buffer consists of OKbbbbd+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const std::vector<uint8_t> &buf, const string &filename) {
  // check the ___OK___ data byte, which should be the first 8 bytes
  if (buf.at(0) == 95 && buf.at(1) == 95 && buf.at(2) == 95 && buf.at(3) == 79 && buf.at(4) == 75 && buf.at(5) == 95 && buf.at(6) == 95 && buf.at(7) == 95) { // O = 79 and K = 75
    // check next four bytes as binary integers to get numbytes,
    
    // write to file the 
    write_file(filename, buf, 12); // only return the d+ bytes after to the file.
  }
  
}

/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  // send request for key
  // make sure key is of kblock length 
  std::vector<uint8_t> sendKey(REQ_KEY.begin(), REQ_KEY.end());

  // loop it until RBlock is correct size
  int padding = LEN_RKBLOCK - sendKey.size();
  while (padding > 0) { // add pad0 to end of vector
    sendKey.push_back((uint8_t) 0); // append a zero character
    padding--;
  }
  sendKey.resize(LEN_RKBLOCK);
  if (send_reliably(sd, sendKey)) { // key request sent
      std::vector<uint8_t> msg = reliable_get_to_eof(sd);
      // check if server exists
      cout << "got into file\n";
      // make sure we get correct public key length
      if (write_file(keyfile, msg, 0)) // write to keyfile
        cout << "it worked\n";
  }
  // NB: These asserts are to prevent compiler warnings (send reliable)
  //assert(sd);
  //assert(keyfile.length() > 0);
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
  auto res = send_cmd(sd, pubkey, REQ_GET, ablock_sss(user, pass, getname));
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
  auto res = send_cmd(sd, pubkey, REQ_ALL, ablock_sss(user, pass, allfile));
  send_result_to_file(res, allfile + ".file.dat");
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);
}
