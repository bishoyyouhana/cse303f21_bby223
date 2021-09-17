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
///@param block 
///
///@return true value if it's a kblock

bool is_kblock(vector <uint8_t> &block){
  for(size_t i =0; i<block.size();i++){
    if ((block[i] !=0) && (REQ_KEY[i] != block[i]))
    {
        return false; //not a kblock
    }
  }
  return true;
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

  vector <uint8_t> request(LEN_RKBLOCK);
  //better to define a variable 'position' since it will be used elsewhere
  vector <uint8_t>::iterator position = request.begin();
  int length;
  //client not requesting anything
  if((length = reliable_get_to_eof_or_n(sd, position, LEN_RKBLOCK)) == -1) {
    return false;
  }
  //handle the key if the block is a kblock
  if(is_kblock(request)) { //request?
    // key request
    //handle_key(sd, pri, pub, storage);
    handle_key(sd, pub);
    return false;
  }

  //extract the cmd from the storage object
  //1 - RSA decryption
  vector <uint8_t> decrypted(LEN_RBLOCK_CONTENT);
  int numBytes;
  if((numBytes = RSA_private_decrypt(length, request.data(), decrypted.data(), pri, RSA_PKCS1_OAEP_PADDING)) != LEN_RBLOCK_CONTENT) { //RSA_private_decrypt?
    send_reliably(sd,RES_ERR_CRYPTO ); 
    //error
    return false;
  }
  //cout<< decrypted<<endl;
  //2- get the command requested
  /*
  unsigned char buffer[256]; 
  string decryptedString;
  for(int i = 0; i < decrypted.size(); i++) {
      buffer[i] = decrypted.at(i);
    }
  //string cmd_requested((char*)decrypted, 7); //fix number
  //set the aeskey 
  for (int i = 0; i < buffer.size(); i++) {
        decryptedString += buffer[i];
    }
    */
  //vector <uint8_t> key(decryptedRBlock.begin() + 3, decryptedRBlock.begin() + 51); // find index
  int len_ablock = decrypted.size(); //make sure length matches request 


  cout << "we reached this point"<<endl;

  //3- get the ablock 
  vector<uint8_t> ablock(len_ablock);
  position = ablock.begin(); // no need to define a new one
  if(reliable_get_to_eof_or_n(sd, position, len_ablock) == -1) {
    //error reliable_get_to_eof_or_n() failed
    return false;
  } //uint8_t
  //4- decrypt the ablock
  //vector<uint8_t> AES_key(string((char*)(decrypt + 7), 51).begin(), string((char*)(decrypt +7), 51).end()); //fix number
  vector<uint8_t> AES_key(decrypted.begin()+7, decrypted.end()); //fix number
  EVP_CIPHER_CTX *aes_ctx = create_aes_context(AES_key , false);//AES key needs to be fixed
  vector actual_ablock = aes_crypt_msg(aes_ctx, ablock);

/*
  reset_aes_context(aes_ctx, AES_key, true);//AES key needs to be fixed, also is this necessary?
  if(!actual_ablock.size()) {
    actual_ablock = aes_crypt_msg(aes_ctx, RES_ERR_CRYPTO);
    if(!send_reliably(sd, actual_ablock)) {
    }
      //cout << "serve_client: (size = " << ablock.size() << ") ablock = " << reinterpret_cast<const char*>(ablock.data()) << endl;
    return false;
  }  
  */
// would this work?
ContextManager aes_reset([&]() { reclaim_aes_context(aes_ctx); });

  cout << "we reached this point"<<endl;

  //execute the function 
  vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, handle_sav,
                                  handle_set, handle_get, handle_all};
  for (size_t i = 0; i < s.size(); ++i){
    if ( == s[i]) {return cmds[i](sd, storage, aes_ctx, ablock);}
  }

//assertions to prevent warnings
  assert(pri);
  assert(storage);
  assert(pub.size() > 0);
  assert(sd);

  return false;
}