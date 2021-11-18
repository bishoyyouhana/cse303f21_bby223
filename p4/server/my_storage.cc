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
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "persist.h"
#include "quotas.h"
#include "storage.h"
#include "quota_tracker.h"

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

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

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
  MyStorage(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
            size_t rqq, double qd, size_t top, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    // TODO: you probably want to free some memory here...
    delete mru;
    delete auth_table;
    delete kv_store;
    delete quota_table;
  }

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
    //cout << "add_user\n";
    // NB: the helper (.o provided) does all the work for this operation :)
    add_user_helper(user, pass, auth_table, storage_file);

    Quotas *newQuotas=new Quotas() ;
    newQuotas->downloads = quota_factory(down_quota, quota_dur);
    newQuotas->uploads = quota_factory(up_quota, quota_dur);
    newQuotas->requests = quota_factory(req_quota, quota_dur);
    this->quota_table->insert(user, newQuotas,[](){});

    return result_t{true, RES_OK, {}};
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
                                   //cout << "set_user_data\n";
    // NB: the helper (.o provided) does all the work for this operation :)
    return set_user_data_helper(user, pass, content, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_user_data_helper(user, pass, who, auth_table);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return auth_helper(user, pass, auth_table);
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

    bool quota_req_err = false;
    bool quota_up_err =false;

    auto lambdaF = [&](Quotas *q)
    {
      if(!q->requests->check_add(1)) quota_req_err = true;
      if(!quota_req_err){if(!q->uploads->check_add(val.size())) quota_up_err = true;}
    };

    if(this->quota_table->do_with(user, lambdaF)==0) return result_t{false, RES_ERR_SERVER, {}};
    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};
    if(quota_up_err) return result_t{false, RES_ERR_QUOTA_UP, {}};

    if(this->kv_store->insert(key,val, [&](){
      //auth.clear();
      this->mru->insert(key);
      //extraLock.lock(); //probably not needed
      log_sv(storage_file, KVENTRY,key , val);   //log_sv(FILE *logfile, const std::string &delim, const std::string &s1, const std::vector<uint8_t> &v1);
      //extraLock.unlock();

      fflush(storage_file);
      fsync(fileno(storage_file));

    })) return result_t{true, RES_OK, {}}; 
    //cout<<"helo"<<endl;
    return result_t{false, RES_ERR_KEY, {}};
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
    //cout<<"kv_get"<<endl;

    auto allow = this->auth(user, pass); 
    if (!allow.succeeded)  return result_t{false, RES_ERR_LOGIN, {}};
    bool quota_req_err =false;
    bool quota_down =false;

    vector<uint8_t> returnValue;

    //main lambda
    auto lambdaf = [&](const vector<uint8_t> &val)
    {
      returnValue = val;
    };

    //lambda to check requests
    auto lambdaReq = [&](Quotas  *q){ if(!q->requests->check_add(1)) quota_req_err = true;};

    //lambda to check quota
    //cout<<returnValue.size()<<endl;
    auto lambdaDown = [&](Quotas  *q){
      if(!q->downloads->check_add(returnValue.size())){ 
        quota_down = true;
      }
    };
    
    this->quota_table->do_with(user, lambdaReq);
    
    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};

    if ((this->kv_store->do_with_readonly(key, lambdaf)) == 0)
    {
      return result_t{false, RES_ERR_KEY, {}};
    }

    if(this->quota_table->do_with(user, lambdaDown)==0) return result_t{false, RES_ERR_SERVER, {}};
    if(quota_down) return result_t{false, RES_ERR_QUOTA_DOWN, {}};


    this->kv_store->do_with_readonly(key, [&](const vector<uint8_t>){this->mru->insert(key);});

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
    //KVDELETE log_sv(storage_file, KVDELETE,key , val); 
    bool quota_req_err =false;

    auto lambdaReq = [&](Quotas  *q){
      if(!q->requests->check_add(1)) quota_req_err = true;
    };


    this->quota_table->do_with(user, lambdaReq);

    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};

    if(this->kv_store->remove(key, [&](){
      this->mru->remove(key);
      log_s(storage_file, KVDELETE,key);  
    })) return {true, RES_OK, {}}; 
    
    return {false, RES_ERR_KEY, {}};                  
      
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    auto r = auth(user, pass);
      if (!r.succeeded){return {false, r.msg, {}};    }

      bool quota_req_err = false;
    bool quota_up_err =false;

auto lambdaF = [&](Quotas  *q)
    {
      if(!q->requests->check_add(1)) quota_req_err = true;
      if(!quota_req_err){if(!q->uploads->check_add(val.size())) quota_up_err = true;}
    };

    if(this->quota_table->do_with(user, lambdaF)==0) return result_t{false, RES_ERR_SERVER, {}};
    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};
    if(quota_up_err) return result_t{false, RES_ERR_QUOTA_UP, {}};


  if (kv_store->upsert(key, val,[&](){
    this->mru->insert(key);
      log_sv(storage_file, KVENTRY,key , val); 

  }, [&](){  //KVUPDATE
this->mru->insert(key);
log_sv(storage_file, KVUPDATE, key, val);
      
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

    bool quota_req_err = false;
    bool quota_down =false;

    auto lambdaReq = [&](Quotas  *q){
      if(!q->requests->check_add(1)) quota_req_err = true;
    };

    auto lambdaDown = [&](Quotas  *q)
    {
      if(!q->downloads->check_add(returnValue.size())) quota_down = true;
    };

    this->quota_table->do_with(user, lambdaReq);
    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};

    
    //main
    kv_store->do_all_readonly([&](string key, vector<uint8_t>){
      returnValue.insert(returnValue.end(), key.begin(), key.end());
      returnValue.push_back('\n');
    }, [](){});
    returnValue.pop_back();


    if(this->quota_table->do_with(user, lambdaDown)==0) return result_t{false, RES_ERR_SERVER, {}};
    if(quota_down) return result_t{false, RES_ERR_QUOTA_DOWN, {}};


    if(returnValue.size() == 0) {
      return {false, RES_ERR_NO_DATA, {}};
    }
    return {true, RES_OK, returnValue};
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    auto allow = auth(user, pass);
    if (!allow.succeeded) return result_t{false, RES_ERR_LOGIN, {}};

    string returnVal="";

    bool quota_req_err = false;
    bool quota_down =false;

    //lambda to check requests
    auto lambdaReq = [&](Quotas  *q){ if(!q->requests->check_add(1)) quota_req_err = true;};

    //lambda to check quota
    auto lambdaDown = [&](Quotas  *q){if(!q->downloads->check_add(returnVal.size())) quota_down = true;};

    this->quota_table->do_with(user, lambdaReq);
    if(quota_req_err) return result_t{false, RES_ERR_QUOTA_REQ, {}};
    returnVal=this->mru->get();

    this->quota_table->do_with(user, lambdaDown);
    if(quota_down) return result_t{false, RES_ERR_QUOTA_DOWN, {}};

    if(returnVal.compare("")==0) return result_t{false, RES_ERR_NO_DATA, {}};

    vector<uint8_t> returnValue;
    returnValue.insert(returnValue.begin(), returnVal.begin(), returnVal.end());

    return result_t{true, RES_OK, returnValue};

  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    //cout << "shutdown\n";
    // NB: Based on how the other methods are implemented in the helper file, we
    //     need this command here:
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    //cout << "save_file\n";
    // NB: the helper (.o provided) does all the work for this operation :)
    return save_file_helper(auth_table, kv_store, filename, storage_file);
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    //cout << "load_file\n";
    // NB: the helper (.o provided) does all the work from p1/p2/p3 for this
    //     operation.  Depending on how you choose to implement quotas, you may
    //     need to edit this.
    storage_file = fopen(filename.c_str(), "rb");
    if (storage_file == nullptr){  
      storage_file = fopen(filename.c_str(), "wb"); 
      return {true, "File not found: " + filename, {}};
    }
    this->mru->clear();
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
        
        Quotas *newQuotas = new Quotas();
        newQuotas->downloads = quota_factory(down_quota, quota_dur);
        newQuotas->uploads = quota_factory(up_quota, quota_dur);
        newQuotas->requests = quota_factory(req_quota, quota_dur);
        this->quota_table->insert(new_user.username, newQuotas,[&](){});

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
