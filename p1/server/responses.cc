#include <cassert>
#include <iostream>
#include <string>

#include "../common/crypto.h"
#include "../common/net.h"

#include "responses.h"

using namespace std;

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_all() is not implemented\n";
  // parse through aBlock to find username and password
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  // https://www.programiz.com/cpp-programming/string-int-conversion
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
  // now use the lengths to properly substring the buffer for user and password
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->get_all_users(user, pass);
  if (result.succeeded) {
    std::string msg = result.msg;
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_set() is not implemented\n";
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
  // int bLen = std::stoi(str.substr(16,1));
  // now use the lengths to properly substring the buffer for user and password and content
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);
  const std::vector<uint8_t> b(str.begin()+32+userLen+passLen, str.end());

  // let storage handle and get its msg
  Storage::result_t result = storage->set_user_data(user, pass, b);
  if(result.succeeded) {
    std::string msg = result.msg;
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_get() is not implemented\n";
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
   int nLen = std::stoi(str.substr(16,1));
  // now use the lengths to properly substring the buffer for user and password and name
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);
  const std::string name = str.substr(32+userLen+passLen, nLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->get_user_data(user, pass, name);
  if(result.succeeded) {
    std::string msg = result.msg;
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  cout << "responses.cc::handle_reg() is not implemented\n";
  // parse through aBlock to find username and password
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
  // now use the lengths to properly substring the buffer for user and password
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->add_user(user, pass);
  if (result.succeeded) {
    std::string msg = result.msg;
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  // cout << "responses.cc::handle_key() is not implemented\n";
  // do reliable send of pubfile on socket sd
  send_reliably(sd, pubfile);
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubfile.size() > 0);
  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  cout << "responses.cc::handle_bye() is not implemented\n";
  // parse through aBlock to find username and password
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
  // now use the lengths to properly substring the buffer for user and password
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);

  // let storage handle and see if user is authentic
  Storage::result_t result = storage->auth(user, pass);
  if (result.succeeded) // exit the client
    return true;
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_sav() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  // parse through aBlock to find username and password
  std::string str(req.begin(), req.end());
  // assume length will be one byte long, cuz max pass and user is 64
  int userLen = std::stoi(str.substr(0,1));
  int passLen = std::stoi(str.substr(8,1));
  // now use the lengths to properly substring the buffer for user and password
  const std::string user = str.substr(32,userLen);
  const std::string pass = str.substr(32+userLen, passLen);

  // let storage handle and see if user is authentic
  Storage::result_t result = storage->auth(user, pass);
  if (result.succeeded) // persist the file
    storage->save_file();
  assert(sd);
  assert(storage);
  assert(ctx);
  assert(req.size() > 0);
  return false;
}
