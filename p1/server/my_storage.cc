#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

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
      : auth_table(authtable_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    //cout << "my_storage.cc::add_user() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    //create salt
    uint8_t salt;
    AuthTableEntry new_user;
    int success= RAND_bytes(&salt, sizeof(salt));

    if(success == 0){
      return {false, RES_ERR_SERVER, {}};
    }
    
    //hash the password
    vector<uint8_t> hashPass;
    hashPass.reserve(SHA256_DIGEST_LENGTH);

    vector<uint8_t> password(pass.begin(), pass.end());
    hashPass.insert(hashPass.end(), password.begin(), password.end());
    hashPass.push_back(salt);

    //no need for context
    SHA256(password.data(), hashPass.size(), hashPass.data());

    vector<uint8_t> saltVec;
    saltVec.reserve(SHA256_DIGEST_LENGTH);
    saltVec.push_back(salt);

    vector<uint8_t> content;

    vector<uint8_t> usernameVec(user.begin(), user.end());
    new_user.username.insert(new_user.username.end(), usernameVec.begin(), usernameVec.end());

    //vector<uint8_t> saltVec(salt.begin(), salt.end());
    new_user.salt.insert(new_user.salt.end(), saltVec.begin(), saltVec.end());

    //vector<uint8_t> profVec(profile.begin(), profile.end());
    new_user.content.insert(new_user.content.end(), content.begin(), content.end());

    vector<uint8_t> passVec(pass.begin(), pass.end());
    new_user.pass_hash.insert(new_user.pass_hash.end(), hashPass.begin(), hashPass.end());
    
    
    auth_table->insert(user, new_user,[](){});
  
    assert(user.length() > 0);
    assert(pass.length() > 0);
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
    cout << "my_storage.cc::set_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
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
    cout << "my_storage.cc::get_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(who.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    cout << "my_storage.cc::get_all_users() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    cout << "my_storage.cc::auth() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() { //don't implement in proj1
    cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() { //persist
    //cout << "my_storage.cc::save_file() is not implemented\n";
    vector<uint8_t> result;
    vector<uint8_t> AUTHENTRYvec(AUTHENTRY.begin(), AUTHENTRY.end());
    result.insert(result.end(), AUTHENTRY.begin(), AUTHENTRY.end());
    uint8_t bytesUsed;

    //Necessary to get acces we need to use f.
    auto lambdaF = [&](string, const AuthTableEntry &user){ //by reference capture 
    result.push_back(static_cast<uint8_t>(user.username.size()));
    result.push_back(static_cast<uint8_t>(sizeof(user.salt)));
    result.push_back(static_cast<uint8_t>(sizeof(user.pass_hash)));
    result.push_back(static_cast<uint8_t>(sizeof(user.content)));
    
    //result.push_back(static_cast<uint8_t>(user.username));
    /*
    result.push_back(user.salt);
    result.push_back((user.pass_hash).begin(),(user.pass_hash).end());
    result.push_back((user.content).begin(),(user.content).end());
    */
    vector<uint8_t> usernameVec(user.username.begin(), user.username.end());
    result.insert(result.end(), usernameVec.begin(), usernameVec.end());
    result.insert(result.end(), user.salt.begin(), user.salt.end());
    result.insert(result.end(), user.pass_hash.begin(), user.pass_hash.end());
    result.insert(result.end(), user.content.begin(), user.content.end());

    bytesUsed =  static_cast<int>(sizeof(user.salt)) + static_cast<int>(sizeof(user.pass_hash)) + 
                          static_cast<int>(sizeof(user.content))+ (user.username.size());
    };
  //call the lambda
  this->auth_table->do_all_readonly(lambdaF,[](){});
  //lambdaF(*auth_table);
    
    while(bytesUsed%8 !=0){
      result.push_back('\0');
      bytesUsed+= 1;
    }

    string currentFileName = this->filename;
    string tempFileName = currentFileName + ".tmp";
    FILE *storage_file = fopen(tempFileName.c_str(), "w+");

    //while(bytesUsed%8 != 0){}

    if (fputs((const char*) result.data(), storage_file) == EOF) {
      //error
      string msg = "File could not save";
      return result_t{false, msg, {}};
    }

    if (rename(tempFileName.c_str(), currentFileName.c_str())) {
      string msg = "File could not be renamed";
      return result_t{false, msg, {}};
  }
  
  return result_t{true, RES_OK, {}};
    
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    //clear the tables first
    this->auth_table->clear();
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    char buffer[64];
    vector<uint8_t> data; 
    data.reserve(LEN_PROFILE_FILE);
    
    while (fgets(buffer, sizeof(buffer), storage_file)) {
      data.push_back(*buffer);
    }
    
    uint8_t pointer =8;
      string user;
      unsigned int user_len;
      string salt;
      unsigned int salt_len;
      string pass;
      unsigned int pass_len;
      string profile;
      unsigned int profile_len;

    while(pointer < data.size()){
      //len username, len salt, len pass, len profile

      user_len = data.at(pointer);
      pointer += 8;
      salt_len = data.at(pointer);
      pointer += 8;
      pass_len = data.at(pointer);
      pointer += 8;
      profile_len = data.at(pointer);
      pointer += 8;

      if (user_len> LEN_UNAME) {
        string msg = "Username too long";
        return result_t{false, msg, {}};
      }

      if (salt_len> LEN_SALT) {
        string msg = "Salt too long";
        return result_t{false, msg, {}};
      }

      if (pass_len> LEN_PASSHASH) {
        string msg = "Password too long";
        return result_t{false, msg, {}};
      }

      if (profile_len> LEN_PROFILE_FILE) {
        string msg = "Profile too long";
        return result_t{false, msg, {}};
      }

      user = data.at(pointer);
      pointer += user_len;
      salt = data.at(pointer);
      pointer += salt_len;
      pass = data.at(pointer);
      pointer += pass_len;
      profile = data.at(pointer);
      pointer += profile_len;
      
      AuthTableEntry new_user;
      vector<uint8_t> usernameVec(user.begin(), user.end());
      new_user.username.insert(new_user.username.end(), usernameVec.begin(), usernameVec.end());
      //new_user.username = user;
      vector<uint8_t> saltVec(salt.begin(), salt.end());
      new_user.salt.insert(new_user.salt.end(), saltVec.begin(), saltVec.end());

      vector<uint8_t> profVec(profile.begin(), profile.end());
      new_user.content.insert(new_user.content.end(), profVec.begin(), profVec.end());

      vector<uint8_t> passVec(pass.begin(), pass.end());
      new_user.pass_hash.insert(new_user.pass_hash.end(), passVec.begin(), passVec.end());

      pointer += 8;
    }

    //cout << "my_storage.cc::save_file() is not implemented\n";
    //return result_t{false, RES_ERR_UNIMPLEMENTED, {}};
    return result_t{true, "Successfuly saved object", {}};
  }
};

/// Create an empty Storage object and specify the file from which it should be
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
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
