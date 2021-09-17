#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;

///helper method that checks if the block given is a kblock
///
///@param block the block to check 
///
///@return true value if it's a kblock

bool is_kblock(vector <uint8_t> &block){
  /*for(size_t i =0; i<block.size();i++){
    if ((block[i] !=0) && (REQ_KEY[i] != block[i]))
    {
        return false; //not a kblock
    }
  } */
  std::string str(block.begin(), block.end());
  if (str.substr(0,8) == REQ_KEY)
    return true;
  return false;
}


/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  //cout << "parsing.cc::parse_request() is not implemented\n";
  // NB: These assertions are only here to prevent compiler warnings

  std::vector<uint8_t> request(LEN_RKBLOCK);
  //better to define a variable 'position' since it will be used elsewhere
  //vector <uint8_t>::iterator position = request.begin();
  int length;
  //client not requesting anything
  if((length = reliable_get_to_eof_or_n(sd, request.begin(), LEN_RKBLOCK)) == -1) {
    return false;
  }
  //handle the key if the block is a kblock
  if(is_kblock(request)) { //request?
    // key request
    //handle_key(sd, pri, pub, storage);
    //handle_key(sd, pub);
    // send key over to Client
    handle_key(sd, pub);
    return false;
  }
  //extract the cmd from the storage object
  //1 - RSA decryption
  //vector <uint8_t> decrypted;
  //decrypted.reserve(LEN_RKBLOCK);

  // unsigned char* buffer;
  std::vector<uint8_t> decrypted(RSA_size(pri));
  if(RSA_private_decrypt(LEN_RKBLOCK, request.data(), decrypted.data(), pri, RSA_PKCS1_OAEP_PADDING) == -1) { //RSA_private_decrypt?
    send_reliably(sd,RES_ERR_CRYPTO ); 
    //error
    return false;
  }
  // string str(reinterpret_cast<char*>(buffer));
  // vector <uint8_t> decrypted (str.begin(), str.end());

  //decrypted.reserve(LEN_RKBLOCK);
  //decrypted.insert(decrypted.begin(),buffer); 
 
  //2- get the command requested 
  
  //rblock 

  //string str(reinterpret_cast<char *>(buffer));
  std::vector<uint8_t> aeskey(decrypted.begin()+8, decrypted.begin()+56); //aeskey
  EVP_CIPHER_CTX *aes_ctx; 
  // uint8_t ablockLength; 
  // memcpy(&ablockLength, decrypted.data() + 56, sizeof(uint8_t)); //ablock length
  size_t ablockLength;
  memcpy(&ablockLength, decrypted.data() + 56, sizeof(size_t));
  std::string cmd(decrypted.begin(), decrypted.begin()+8); //command

  // ContextManager aes_reset([&]() { reclaim_aes_context(aes_ctx); });

  std::vector<uint8_t> ablock(ablockLength);
  reliable_get_to_eof_or_n(sd, ablock.begin(), (int) ablockLength); //check server size  fix this

  // std::vector<uint8_t> context;
  aes_ctx = create_aes_context(aeskey, false); /// Create context
  std::vector<uint8_t>  context = aes_crypt_msg(aes_ctx, ablock);

  if (context.size() == 0) { //cannot decrypt?
    send_reliably(sd, RES_ERR_CRYPTO);
    return false;
  }
          
  reset_aes_context(aes_ctx, aeskey, true);

  //execute the function 
  std::vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};
  for (size_t i = 0; i < s.size(); ++i){
    if (cmd == s[i]) {
      bool server = cmds[i](sd, storage, aes_ctx, context);
      // reclaim ctx for memory
      reclaim_aes_context(aes_ctx);
      return server;
      }
  }

//assertions to prevent warnings

  return false;
}