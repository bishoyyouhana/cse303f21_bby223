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

  vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  vector <unsigned char> request(LEN_RKBLOCK);
  vector<unsigned char>::iterator position = request.begin();

  //client not requesting anything
  if(reliable_get_to_eof_or_n(sd, position, LEN_RKBLOCK) == -1) {
    return false;
  }

  if(request.size() == LEN_RKBLOCK && !strncmp(reinterpret_cast<const char*>(request.data()), "KEY", 3)) {
    // key request
    handle_key(sd, pub);
    return false;
  }

  //extract the cmd from the storage object
  //1 - RSA decryption
  unsigned char decrypt[LEN_RBLOCK_CONTENT];
  int numBytes;
  if((numBytes = RSA_private_decrypt(LEN_RKBLOCK, request.data(), decrypt, pri, RSA_PKCS1_OAEP_PADDING)) != LEN_RBLOCK_CONTENT) {
    //error
  }

  //2- get the command requested

  //cout << "serve_client: numBytes = " << numBytes << endl;
  string cmd_requested((char*)decrypt, 3);
  //cout << "serve_client: found cmd_requested = " << cmd_requested[0] << cmd_requested[1] << cmd_requested[2] << endl;

  //set the aeskey from string to vector 
  //vec AES_key = vec_from_string(string((char*)(decrypt + 3), 48));
  int *len_ablock = (int32_t*)(decrypt + 51); //didn't work otherwise, not sure what's happening


  //cout << "serve_client: len_ablock = " << *len_ablock << endl;

  //3- get the ablock 
  vector<unsigned char> ablock(*len_ablock);
  position = ablock.begin(); // no need to define a new one
  if(reliable_get_to_eof_or_n(sd, position, *len_ablock) == -1) {
    //error
    return false;
  }
  //4- decrypt the ablock
  vector<unsigned char> AES_key(string((char*)(dec + 3), 48).begin(), string((char*)(dec + 3), 48).end());
  EVP_CIPHER_CTX *aes_ctx = create_aes_context(AES_key , false);//AES key needs to be fixed
  vector actual_ablock = aes_crypt_msg(aes_ctx, ablock);


  reset_aes_context(aes_ctx, AES_key, true);//AES key needs to be fixed, also is this necessary
  if(!actual_ablock.size()) {
    actual_ablock = aes_crypt_msg(aes_ctx, RES_ERR_CRYPTO);
    if(!send_reliably(sd, actual_ablock)) {
    }
      //cout << "serve_client: (size = " << ablock.size() << ") ablock = " << reinterpret_cast<const char*>(ablock.data()) << endl;
    return false;
  }  

  
  //execute the function 
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};
  for (size_t i = 0; i < s.size(); ++i){
    if (cmd_requested == s[i]) {return cmds[i](sd, storage, aes_ctx, ablock);}
  }

//assertions to prevent warnings
  assert(pri);
  assert(storage);
  assert(pub.size() > 0);
  assert(sd);

  return false;
}
/*
bool is_kblock(vector<unsigned char> block){
  return false;
}
*/