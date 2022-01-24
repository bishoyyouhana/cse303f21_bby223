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
  // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->get_all_users(user, pass);
  if (result.succeeded) {
    // This should just be "___OK___"
    std::string msg = result.msg;
    // this is the content block
    std::vector<uint8_t> content = result.data;
    // find length of content and append everything to send to client
    size_t contentLen = content.size();
    std::vector<uint8_t> block(msg.begin(), msg.end());
    block.insert(block.end(), (uint8_t*) &contentLen, ((uint8_t*) &contentLen) + sizeof(contentLen));
    block.insert(block.end(), content.begin(), content.end());
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, block);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }

  // NB: These asserts are to prevent compiler warnings
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
  // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);
  //int cLen = req.at(16);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);
  std::vector<uint8_t> content(req.begin() + 32 + uLen + pLen, req.end());

  // let storage handle and get its msg
  Storage::result_t result = storage->set_user_data(user, pass, content);
  if(result.succeeded) {
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
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
   // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);
  int nLen = req.at(16);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);
  std::string name(req.begin() + 32 + uLen + pLen, req.begin() + 32 + uLen + pLen + nLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->get_user_data(user, pass, name);
  if(result.succeeded) {
    // This should just be "___OK___"
    std::string msg = result.msg;
    // this is the content block
    std::vector<uint8_t> content = result.data;
    // find length of content and append everything to send to client
    size_t contentLen = content.size();
    content.resize(contentLen);
    std::vector<uint8_t> block(msg.begin(), msg.end());
    block.insert(block.end(), (uint8_t*) &contentLen, ((uint8_t*) &contentLen) + sizeof(contentLen));
    block.insert(block.end(), content.begin(), content.end());
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, block);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
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
  // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);

  // let storage handle and get its msg
  Storage::result_t result = storage->add_user(user, pass);
  if (result.succeeded) {
    std::string msg = result.msg;
  
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
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
  // do reliable send of pubfile on socket sd
  send_reliably(sd, pubfile);
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
   // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);

  // let storage handle and see if user is authentic
  Storage::result_t result = storage->auth(user, pass);
  if (result.succeeded) {// exit the client
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
    return true;
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
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
  // parse through aBlock to find username and password
  // assume length will be one byte long, cuz max pass and user is 64
  int uLen = req.at(0);
  int pLen = req.at(8);

  // Get the user and pass using the lengths given by aBlock
  std::string user(req.begin() + 32, req.begin() + 32 + uLen);
  std::string pass(req.begin() + 32 + uLen, req.begin() + 32 + uLen + pLen);

  // let storage handle and see if user is authentic
  Storage::result_t result = storage->auth(user, pass);
  if (result.succeeded) {// persist the file
    Storage::result_t result2 = storage->save_file();
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  else { // Error occured, send Client encrypted error message
    std::string msg = result.msg;
    // aes encrypt the msg and send it back to Client
    std::vector<uint8_t> encryptedBlock = aes_crypt_msg(ctx, msg);
    // send to client via socket
    send_reliably(sd, encryptedBlock);
  }
  return false;
}
