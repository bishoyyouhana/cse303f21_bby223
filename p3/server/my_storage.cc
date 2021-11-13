#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <mutex>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

  /// The open file
  FILE *storage_file = nullptr;

  // extra lock 
  std::mutex extraLock;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

    virtual vector<uint8_t> hash_pass(string pass, vector<uint8_t> &salt)
  {
    vector<uint8_t> toHash;
    vector<uint8_t> password;
    vector<uint8_t> saltVec;

    password.insert(password.begin(), pass.begin(), pass.end());

    toHash.insert(toHash.begin(), password.begin(), password.end());
    toHash.insert(toHash.end(), salt.begin(), salt.end());

    vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, toHash.data(), toHash.size());
    SHA256_Final(hash.data(), &sha256);

    return hash;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    vector<uint8_t> saltVec(LEN_SALT);
    AuthTableEntry new_user;                      //user we will add
    int success = RAND_bytes(saltVec.data(), LEN_SALT); //salt

    if (success == 0)
    {
      return {false, RES_ERR_SERVER, {}};
    }

    vector<uint8_t> hashedPass = hash_pass(pass, saltVec);
    //inserting user
    new_user.username = user;
    //new_user.username.insert(new_user.username.begin(), user.begin(), user.end());
    new_user.salt= saltVec;
    new_user.pass_hash= hashedPass;

    bool check = auth_table->insert(user, new_user, [&]() {
      vector<uint8_t> AUTHEN;
      //AUTHEN.reserve(AUTHENTRY.length());
      AUTHEN.insert(AUTHEN.begin(),AUTHENTRY.begin(), AUTHENTRY.end());
      
      int bytesUsed=0;
      string padding = "\0";
      extraLock.lock();
      fwrite(AUTHEN.data(), sizeof(char), AUTHENTRY.length(), storage_file);

      size_t userSize = new_user.username.length();
      size_t saltSize = new_user.salt.size();
      size_t hashSize = new_user.pass_hash.size();
      size_t contentSize = new_user.content.size();

      fwrite(&userSize, sizeof(size_t), 1, storage_file);
      fwrite(&saltSize, sizeof(size_t), 1, storage_file);
      fwrite(&hashSize, sizeof(size_t), 1, storage_file);
      fwrite(&contentSize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> usernameVec(userSize);
      usernameVec.insert(usernameVec.begin(), new_user.username.begin(), new_user.username.end());
      bytesUsed += fwrite(usernameVec.data(),sizeof(char), userSize, storage_file );

      bytesUsed+= fwrite(new_user.salt.data(), sizeof(uint8_t), saltSize, storage_file);
      bytesUsed += fwrite(new_user.pass_hash.data(), sizeof(uint8_t), hashSize, storage_file);

      if (contentSize > 0) bytesUsed += fwrite(new_user.content.data(), sizeof(uint8_t), contentSize, storage_file);
      //int x = fwrite(&padding, sizeof(char), 8, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();

      fflush(storage_file);
      fsync(fileno(storage_file));

    });

    if (!check)
    {
      //User exists already"
      return result_t{false, RES_ERR_USER_EXISTS, {}}; //return a specific message
    }
    return {true, RES_OK, {}};

  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {

    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)
    {
      return result_t{false, RES_ERR_LOGIN, {}};
    }
    vector<uint8_t> diff(8);
    //new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
    diff.insert(diff.begin(),AUTHDIFF.begin(), AUTHDIFF.end());

    auto lambdaF = [&](AuthTableEntry &test)
    {
      test.content = content;

      string padding = "\0";
      int bytesUsed=0;

      extraLock.lock();
      fwrite(diff.data(), sizeof(char), AUTHDIFF.length(), storage_file);

      size_t userSize = test.username.length();
      size_t profLen = test.content.size();
      fwrite(&userSize, sizeof(size_t), 1, storage_file);
      fwrite(&profLen, sizeof(size_t), 1, storage_file);

      vector<uint8_t> usernameVec(userSize);
      usernameVec.insert(usernameVec.begin(), test.username.begin(), test.username.end());
      bytesUsed += fwrite(usernameVec.data(),sizeof(char), userSize, storage_file );

      if(test.content.size() > 0) bytesUsed += fwrite(test.content.data(), sizeof(uint8_t), profLen, storage_file);

      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();
      fflush(storage_file);
      fsync(fileno(storage_file));
    };

    //AuthTableEntry new_user;
    if (this->auth_table->do_with(user, lambdaF) == 0)
      return result_t{false, RES_ERR_NO_DATA, {}};
    //couts not working
    if(content.size()==0){return result_t{false, RES_ERR_NO_DATA, {}};}
    //std::cout.flush();

    return {true, RES_OK, {}};

  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
 
    auto allow = auth(user, pass);

    if (!allow.succeeded)
    {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    vector<uint8_t> content;
    auto lamdaf = [&](const AuthTableEntry &user)
    {
      content = user.content;
    };
    if (!this->auth_table->do_with_readonly(who, lamdaf))
    {
      return result_t{false, RES_ERR_SERVER, {}};
    }

    if ( content.size()== 0)
    {
      return result_t{false, RES_ERR_NO_DATA, {}};
    }
    return result_t{true, RES_OK, content};

  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {

    auto allow = auth(user, pass);

    if (!allow.succeeded) return result_t{false, RES_ERR_LOGIN, {}};
    

    vector<uint8_t> allUsers;
    auto lambdaf = [&](std::string tmpuser, const AuthTableEntry& )
    {
      //vector<uint8_t> username(LEN_UNAME);
      allUsers.insert(allUsers.end(), tmpuser.begin(), tmpuser.end());
      //allUsers.push_back(username.begin());
      allUsers.push_back('\n');
    };
    // do_all gets all the users
    this->auth_table->do_all_readonly(lambdaf, []() {});

    allUsers.pop_back();
    return {true, RES_OK, allUsers};

  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {

    string authUser;
    vector<uint8_t> hashPass;
    vector<uint8_t> saltVec(LEN_SALT);

    //retrieving necessary data
    auto lamdaF = [&](const AuthTableEntry &tmpuser)
    {
      //if((auth_table->do_with_readonly(user, [&](const AuthTableEntry& tmpUser){
      authUser = tmpuser.username;
      //saltVec.insert(saltVec.begin(), tmpuser.salt.begin(), tmpuser.salt.end());
      saltVec = tmpuser.salt;
      hashPass = tmpuser.pass_hash;
    };
    this->auth_table->do_with_readonly(user, lamdaF);

    vector<uint8_t> passVec = hash_pass(pass, saltVec);

    if (passVec == hashPass) //will this work?
    {
      return result_t{true, RES_OK, {}};
    }

    //wrong password
    return result_t{false, RES_ERR_LOGIN, {}};

  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)  return result_t{false, RES_ERR_LOGIN, {}};

    vector<uint8_t> kv(8);
    kv.insert(kv.begin(),KVENTRY.begin(), KVENTRY.end());
    string padding = "\0";

    if(kv_store->insert(key,val, [&](){

      int bytesUsed=0;
      //auth.clear();
      extraLock.lock();
      fwrite(kv.data(),sizeof(char), 8, storage_file);

      size_t keySize = key.length();
      size_t valSize = val.size();

      fwrite(&keySize, sizeof(size_t), 1, storage_file);
      fwrite(&valSize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> keyV(keySize);
      keyV.insert(keyV.begin(), key.begin(), key.end());

      bytesUsed += fwrite(keyV.data(), sizeof(char), keySize, storage_file);
      bytesUsed+= fwrite(val.data(), sizeof(uint8_t), valSize, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();

      fflush(storage_file);
      fsync(fileno(storage_file));

    })) return {true, RES_OK, {}}; 
    
    return {false, RES_ERR_KEY, {}};
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {

    auto allow = this->auth(user, pass); 
    if (!allow.succeeded)  return result_t{false, RES_ERR_LOGIN, {}};

    vector<uint8_t> returnValue;
    auto lambdaf = [&](const vector<uint8_t> &val)
    {
      returnValue = val;
    };

    if ((this->kv_store->do_with_readonly(key, lambdaf)) == 0)
    {
      return result_t{false, RES_ERR_KEY, {}};
    }

    return {true, RES_OK, {returnValue}};  

  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {

    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)  return result_t{false, RES_ERR_LOGIN, {}};

    vector<uint8_t> del(8);
    //new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
    del.insert(del.begin(),KVDELETE.begin(), KVDELETE.end());
    
    if(this->kv_store->remove(key, [&](){
      string padding = "\0";
      int bytesUsed=0;

      extraLock.lock();
      fwrite(del.data(), sizeof(char), KVDELETE.length(), storage_file);
      size_t keySize = key.length();
      fwrite(&keySize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> keyV(keySize);
      keyV.insert(keyV.begin(), key.begin(), key.end());
      bytesUsed += fwrite(keyV.data(), sizeof(char), keySize, storage_file);
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();
      fflush(storage_file);
      fsync(fileno(storage_file));

    })) return {true, RES_OK, {}}; 
    
    return {false, RES_ERR_SERVER, {}};

  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    auto r = auth(user, pass);
  if (!r.succeeded){return {false, r.msg, {}};    }

    vector<uint8_t> kv(8);
    kv.insert(kv.begin(),KVENTRY.begin(), KVENTRY.end());

    vector<uint8_t> update(8);
    update.insert(update.begin(),KVUPDATE.begin(), KVUPDATE.end());
    string padding = "\0";

  if (kv_store->upsert(key, val,[&](){
    
      int bytesUsed=0;
      //auth.clear();
      extraLock.lock();
      fwrite(kv.data(),sizeof(char), 8, storage_file);

      size_t keySize = key.length();
      size_t valSize = val.size();

      fwrite(&keySize, sizeof(size_t), 1, storage_file);
      fwrite(&valSize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> keyV(keySize);
      keyV.insert(keyV.begin(), key.begin(), key.end());

      bytesUsed += fwrite(keyV.data(), sizeof(char), keySize, storage_file);
      bytesUsed+= fwrite(val.data(), sizeof(uint8_t), valSize, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();

      fflush(storage_file);
      fsync(fileno(storage_file));

  }, [&](){  //KVUPDATE

      int bytesUsed=0;
      //auth.clear();
      extraLock.lock();
      fwrite(update.data(),sizeof(char), 8, storage_file);

      size_t keySize = key.length();
      size_t valSize = val.size();

      fwrite(&keySize, sizeof(size_t), 1, storage_file);
      fwrite(&valSize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> keyV(keySize);
      keyV.insert(keyV.begin(), key.begin(), key.end());

      bytesUsed += fwrite(keyV.data(), sizeof(char), keySize, storage_file);
      bytesUsed+= fwrite(val.data(), sizeof(uint8_t), valSize, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      extraLock.unlock();
      fflush(storage_file);
      fsync(fileno(storage_file));
  })) 
    return {true, RES_OKINS, {}};
  return {true, RES_OKUPD, {}}; 

  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {

    auto allow = auth(user, pass);
    if (!allow.succeeded) return result_t{false, RES_ERR_LOGIN, {}};
    vector<uint8_t> returnValue;

    kv_store->do_all_readonly([&](string key, vector<uint8_t>){
      returnValue.insert(returnValue.end(), key.begin(), key.end());
      returnValue.push_back('\n');
  }, [](){});

  returnValue.pop_back();

  if(returnValue.size() == 0) {
    return {false, RES_ERR_NO_DATA, {}};
  }
  return {true, RES_OK, returnValue};

  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() { 
    fclose(storage_file);
    //not empty
    //cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {

    string currentFileName = this->filename;
    string tempFileName = this->filename + ".tmp";
    FILE *tmp_file = nullptr;
    
    //fclose(storage_file);
    //storage_file = fopen(tempFileName.c_str(), "wb");

    vector<uint8_t> AUTHEN(8);
    //new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
    AUTHEN.insert(AUTHEN.begin(),AUTHENTRY.begin(), AUTHENTRY.end());

    vector<uint8_t> kv(8);
    kv.insert(kv.begin(),KVENTRY.begin(), KVENTRY.end());

    auth_table->do_all_readonly ([&](string , const AuthTableEntry table) {
      if(tmp_file == nullptr) tmp_file = fopen(tempFileName.c_str(), "wb");

      string padding = "\0";
      int bytesUsed=0;
      fwrite(AUTHEN.data(), sizeof(char), AUTHENTRY.length(), tmp_file);

      size_t userSize = table.username.length();
      size_t saltSize = table.salt.size();
      size_t hashSize = table.pass_hash.size();
      size_t contentSize = table.content.size();

      fwrite(&userSize, sizeof(size_t), 1, tmp_file);
      fwrite(&saltSize, sizeof(size_t), 1, tmp_file);
      fwrite(&hashSize, sizeof(size_t), 1, tmp_file);
      fwrite(&contentSize, sizeof(size_t), 1, tmp_file);

      vector<uint8_t> usernameVec(userSize);
      usernameVec.insert(usernameVec.begin(), table.username.begin(), table.username.end());
      bytesUsed += fwrite(usernameVec.data(),sizeof(char), userSize, tmp_file );

      bytesUsed+= fwrite(table.salt.data(), sizeof(uint8_t), saltSize, tmp_file);
      bytesUsed += fwrite(table.pass_hash.data(), sizeof(uint8_t), hashSize, tmp_file);

      if (contentSize > 0) bytesUsed += fwrite(table.content.data(), sizeof(uint8_t), contentSize, tmp_file);
      //int x = fwrite(&padding, sizeof(char), 8, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), tmp_file);
    
    },[&](){

      kv_store->do_all_readonly ([&](string key, const vector<uint8_t> & value) {

      string padding = "\0";
      int bytesUsed=0;
      //auth.clear();
      fwrite(kv.data(),sizeof(char), 8, tmp_file);

      size_t keySize = key.length();
      size_t valSize = value.size();

      fwrite(&keySize, sizeof(size_t), 1, tmp_file);
      fwrite(&valSize, sizeof(size_t), 1, tmp_file);

      vector<uint8_t> keyV(keySize);
      keyV.insert(keyV.begin(), key.begin(), key.end());

      bytesUsed += fwrite(keyV.data(), sizeof(char), keySize, tmp_file);
      bytesUsed+= fwrite(value.data(), sizeof(uint8_t), valSize, tmp_file);

      //int x = fwrite(&padding, sizeof(char), 8, storage_file);
      
      if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), tmp_file);
    
    },[&](){
      fclose(storage_file);
      fclose(tmp_file);
      rename(tempFileName.c_str(), currentFileName.c_str());
      storage_file = fopen(currentFileName.c_str(), "a+"); 
    });
    });
    //storage_file = fopen(currentFileName.c_str(), "a+"); 
    return result_t{true, RES_OK, {}};
  
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    storage_file = fopen(filename.c_str(), "rb");
    if (storage_file == nullptr){  
      storage_file = fopen(filename.c_str(), "wb"); 
      return {true, "File not found: " + filename, {}};
    }
    this->auth_table->clear();
    this->kv_store->clear();

    size_t userLen, saltLen, passLen, dataLen, keyLen, valLen;

    int bytesUsed=0;
    bool cont = true;
    int x = 0; //just to prevent errors

    vector<uint8_t> AUTHEN(8);
    AUTHEN.insert(AUTHEN.begin(),AUTHENTRY.begin(), AUTHENTRY.end());

    vector<uint8_t> kvkv(8);
    kvkv.insert(kvkv.begin(),KVENTRY.begin(), KVENTRY.end());

    vector<uint8_t> diff(8);
    diff.insert(diff.begin(),AUTHDIFF.begin(), AUTHDIFF.end());

    vector<uint8_t> update(8);
    update.insert(update.begin(),KVUPDATE.begin(), KVUPDATE.end());

    vector<uint8_t> del(8);
    del.insert(del.begin(),KVDELETE.begin(), KVDELETE.end());

    vector<uint8_t> buffer(8);
    x=fread(buffer.data(),sizeof(char), 8, storage_file );

    while(cont){
      //Authentry
      if(equal(AUTHEN.begin(), AUTHEN.end(), buffer.begin())){
        buffer.clear();
        AuthTableEntry new_user;
        bytesUsed =0;
        x=fread(&userLen,sizeof(size_t), 1, storage_file );
        x=fread(&saltLen,sizeof(size_t), 1, storage_file );
        x=fread(&passLen,sizeof(size_t), 1, storage_file );
        x=fread(&dataLen,sizeof(size_t), 1, storage_file );
 
        vector<uint8_t> usernameVec(userLen);
        bytesUsed += fread(usernameVec.data(),sizeof(char), userLen, storage_file );
        new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());

        vector<uint8_t> saltVec(saltLen);
        bytesUsed +=fread(saltVec.data(), sizeof(uint8_t), saltLen, storage_file );
        new_user.salt.insert(new_user.salt.begin(), saltVec.begin(), saltVec.end());

        vector<uint8_t> passVec(passLen);
        bytesUsed +=fread(passVec.data(),sizeof(uint8_t), passLen, storage_file );
        new_user.pass_hash.insert(new_user.pass_hash.begin(), passVec.begin(), passVec.end());
   
        vector<uint8_t> profVec(dataLen);
        if(dataLen>0){   
          bytesUsed +=fread(profVec.data(), sizeof(uint8_t), dataLen, storage_file );
          new_user.content.insert(new_user.content.begin(), profVec.begin(), profVec.end());
        }else{
          new_user.content.reserve(0);
          }
          
        vector<uint8_t> buf(8);
        if((bytesUsed%8)>0) x=fread(buf.data(),sizeof(char), (8-bytesUsed%8), storage_file);
        
        bool check = auth_table->insert(new_user.username, new_user, [&]() {});     
        bytesUsed =0;
        //cout<<"Authentry"<<endl;
        if(!check){
          return result_t{false, RES_ERR_SERVER, {}};
        }
      
      }else if(equal(kvkv.begin(), kvkv.end(), buffer.begin())){ //Kventry
        buffer.clear();
        bytesUsed=0;
        // KV entry
        x=fread(&keyLen,sizeof(size_t), 1, storage_file );
        x=fread(&valLen,sizeof(size_t), 1, storage_file );

        vector<uint8_t> keyVec(keyLen);
        bytesUsed += fread(keyVec.data(),sizeof(char), keyLen, storage_file );

        vector<uint8_t> valVec(valLen);
        bytesUsed +=fread(valVec.data(), sizeof(uint8_t), valLen, storage_file );

        std::string str(keyVec.begin(), keyVec.end());
        bool check = kv_store->insert(str, valVec, [&](){});

        //cout<<"Kventry"<<endl;
        if(!check){
          return result_t{false, RES_ERR_SERVER, {}};
        }

        vector<uint8_t> buf(8);
        if((bytesUsed%8)>0) x=fread(buf.data(),sizeof(char), (8-bytesUsed%8), storage_file);

      }else if(equal(diff.begin(), diff.end(), buffer.begin())){ //AUTHDIFF
      buffer.clear();
      bytesUsed =0;
        x=fread(&userLen,sizeof(size_t), 1, storage_file );
        x=fread(&dataLen,sizeof(size_t), 1, storage_file );

        
        string username = "";
        vector<uint8_t> usernameVec(userLen);
        bytesUsed +=fread(usernameVec.data(), sizeof(uint8_t), userLen, storage_file );
        username.insert(username.begin(), usernameVec.begin(), usernameVec.end());

        vector<uint8_t> profVec(dataLen);
        bytesUsed +=fread(profVec.data(), sizeof(uint8_t), dataLen, storage_file );

        bool check = this->auth_table->do_with(username, [&](AuthTableEntry &user){user.content = profVec;});

        if(!check){ return result_t{false, RES_ERR_SERVER, {}};}
        vector<uint8_t> buf(8);
        if((bytesUsed%8)>0) x=fread(buf.data(),sizeof(char), (8-bytesUsed%8), storage_file);


      }else if(equal(update.begin(), update.end(), buffer.begin())){ //KVUPDATE
      buffer.clear();
      bytesUsed =0;
        x=fread(&keyLen,sizeof(size_t), 1, storage_file );
        x=fread(&valLen,sizeof(size_t), 1, storage_file );

        vector<uint8_t> keyVec(keyLen);
        string key="";
        bytesUsed +=fread(keyVec.data(), sizeof(uint8_t), keyLen, storage_file );
        //username.insert(username.begin(), usernameVec.begin(), usernameVec.end());
        key.insert(key.begin(),keyVec.begin(), keyVec.end());

        vector<uint8_t> valVec(valLen);
        bytesUsed +=fread(valVec.data(), sizeof(uint8_t), valLen, storage_file );

        this->kv_store->upsert(key, valVec, [&](){},[&](){});

        //if(!check){ return result_t{false, RES_ERR_SERVER, {}};}
        vector<uint8_t> buf(8);
        if((bytesUsed%8)>0) x=fread(buf.data(),sizeof(char), (8-bytesUsed%8), storage_file);

      }else if(equal(del.begin(), del.end(), buffer.begin())){ //KVDELETE
      buffer.clear();
      bytesUsed =0;
        x=fread(&keyLen,sizeof(size_t), 1, storage_file );

        vector<uint8_t> keyVec(keyLen);
        string key="";
        bytesUsed +=fread(keyVec.data(), sizeof(uint8_t), keyLen, storage_file );
        key.insert(key.begin(),keyVec.begin(), keyVec.end());
        bool check = this->kv_store->remove(key, [&]() {});

        //cout<<"KVDELETE"<<endl;
        if(!check){ return result_t{false, RES_ERR_SERVER, {}};}
        vector<uint8_t> buf(8);
        if((bytesUsed%8)>0) x=fread(buf.data(),sizeof(char), (8-bytesUsed%8), storage_file);
      }

      buffer.clear();
      x=0;
      x=fread(buffer.data(),sizeof(char), 8, storage_file );
      if(x==8){
        //equal(AUTHEN.begin(), AUTHEN.end(), buffer.begin())
        cont = true;
      }else{
        cont = false;
      }
    }
    fclose(storage_file);
    storage_file = fopen(filename.c_str(), "a+");
    return result_t{true, "Loaded: " + filename, {}};
  };
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
