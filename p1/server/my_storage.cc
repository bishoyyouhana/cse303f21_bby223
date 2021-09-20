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
//#include "../common/file.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage
{
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

  /// Helper function that simplifies hashing
  ///
  /// @param pass   given password in string format
  /// @param salt   salt in vector fomrat
  /// @return hash   hash result

  virtual vector<uint8_t> hash_pass(string pass, vector<uint8_t> salt)
  {
    //cout << "hello in hash_pass" <<endl;
    vector<uint8_t> toHash;
    vector<uint8_t> password;
    vector<uint8_t> saltVec;

    password.insert(password.begin(), pass.begin(), pass.end());
    saltVec.insert(saltVec.begin(), salt.begin(), salt.end());
    toHash.insert(toHash.begin(), password.begin(), password.end());
    toHash.insert(toHash.end(), saltVec.begin(), saltVec.end());

    vector<uint8_t> hash;
    hash.reserve(SHA256_DIGEST_LENGTH);

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
  virtual result_t add_user(const string &user, const string &pass)
  {
    //cout << "add_user called\n";
    //cout << "my_storage.cc::add_user() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    vector<uint8_t> saltVec;
    vector<uint8_t> content;
    unsigned char salt[LEN_SALT];
    AuthTableEntry new_user;                      //user we will add
    int success = RAND_bytes(salt, sizeof(salt)); //salt

    string saltName(reinterpret_cast<char *>(salt));
    saltVec.insert(saltVec.begin(), saltName.begin(), saltName.end());

    if (success == 0)
    {
      return {false, RES_ERR_SERVER, {}};
    }

    //involved a lot of coding before the helper function was created
    vector<uint8_t> hashedPass = hash_pass(pass, saltVec);

    //inserting user
    new_user.username.insert(new_user.username.begin(), user.begin(), user.end());
    new_user.salt.insert(new_user.salt.begin(), saltVec.begin(), saltVec.end());
    new_user.content.insert(new_user.content.begin(), content.begin(), content.end());
    new_user.pass_hash.insert(new_user.pass_hash.begin(), hashedPass.begin(), hashedPass.end());
    bool check = auth_table->insert(user, new_user, []() {});

    if (check == false)
    {
      //User exists already"
      return result_t{false, RES_ERR_USER_EXISTS, {}}; //return a specific message
    }

    //assert(user.length() > 0);
    //assert(pass.length() > 0);
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
                                 const vector<uint8_t> &content)
  {
    //cout << "my_storage.cc::set_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)
    {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    auto lambdaF = [&](AuthTableEntry &user)
    {
      user.content = content;
    };

    //AuthTableEntry new_user;

    if (this->auth_table->do_with(user, lambdaF) == 0)
      return result_t{false, RES_ERR_NO_DATA, {}};

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
                                 const string &who)
  {
    //cout << "my_storage.cc::get_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

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
    if ((this->auth_table->do_with_readonly(who, lamdaf)) == 0)
    {
      return result_t{false, RES_ERR_NO_DATA, {}};
    }
    return result_t{true, RES_OK, content};
    //assert(user.length() > 0);
    //assert(pass.length() > 0);
    //assert(who.length() > 0);
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass)
  {
    //cout << "my_storage.cc::get_all_users() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    auto allow = auth(user, pass);

    if (!allow.succeeded)
    {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    vector<uint8_t> allUsers;
    auto lambdaf = [&](std::string, const AuthTableEntry &tmpuser)
    {
      vector<uint8_t> username(LEN_UNAME);
      username.insert(username.begin(), tmpuser.username.begin(), tmpuser.username.end());
      //allUsers.push_back(username);
      allUsers.push_back('\n');
    };
    // do_all gets all the users
    this->auth_table->do_all_readonly(lambdaf, []() {});

    assert(user.length() > 0);
    assert(pass.length() > 0);

    return {true, RES_OK, allUsers};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass)
  {
    //cout << "my_storage.cc::auth() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    //bool boolean;
    string authUser;
    vector<uint8_t> hashPass;
    vector<uint8_t> saltVec;

    //retrieving necessary data
    auto lamdaF = [&](const AuthTableEntry &tmpuser)
    {
      //if((auth_table->do_with_readonly(user, [&](const AuthTableEntry& tmpUser){
      authUser = tmpuser.username;
      saltVec = tmpuser.salt;
      hashPass = tmpuser.pass_hash;
    };
    this->auth_table->do_with_readonly(user, lamdaF);

    vector<uint8_t> passVec = hash_pass(pass, saltVec);

    if (passVec == hashPass)
    {
      return result_t{true, RES_OK, {}};
    }

    //wrong password
    return result_t{false, RES_ERR_LOGIN, {}};
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown()
  { //don't implement in proj1
    //cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file()
  { //persist
    //cout << "my_storage.cc::save_file() is not implemented\n";
    //cout << "save_file called\n";
    string currentFileName = this->filename;
    string tempFileName = currentFileName + ".tmp";
    FILE *storage_file = fopen(tempFileName.c_str(), "wb");

    vector<uint8_t> padding;
    //vector<uint8_t> AUTHENTRYvec(AUTHENTRY.begin(), AUTHENTRY.end());
    //result.insert(result.begin(), AUTHENTRY.begin(), AUTHENTRY.end());
    uint8_t bytesUsed;
    fwrite(AUTHENTRY.c_str(), AUTHENTRY.length(), 1, storage_file);

    //Necessary to get acces we need to use f.
    auto lambdaF = [&](string, const AuthTableEntry &user) { //by reference capture
      //attemp to create a vector and write everything at once
      /*
    result.push_back(static_cast<uint8_t>(user.username.size()));
    result.push_back(static_cast<uint8_t>(sizeof(user.salt)));
    result.push_back(static_cast<uint8_t>(sizeof(user.pass_hash)));
    result.push_back(static_cast<uint8_t>(sizeof(user.content)));
    
    vector<uint8_t> usernameVec(user.username.begin(), user.username.end());
    result.insert(result.end(), usernameVec.begin(), usernameVec.end());
    result.insert(result.end(), user.salt.begin(), user.salt.end());
    result.insert(result.end(), user.pass_hash.begin(), user.pass_hash.end());

    if(sizeof(user.content) != 0){result.insert(result.end(), user.content.begin(), user.content.end());}

    bytesUsed =  static_cast<int>(sizeof(user.salt)) + static_cast<int>(sizeof(user.pass_hash)) + 
                          static_cast<int>(sizeof(user.content))+ (user.username.size());
    */

      //writing each piece of data separately
      size_t userSize = user.username.size();
      size_t saltSize = sizeof(user.salt);
      size_t hashSize = sizeof(user.pass_hash);
      size_t contentSize = sizeof(user.content);

      fwrite(&userSize, sizeof(size_t), 1, storage_file);
      fwrite(&saltSize, sizeof(size_t), 1, storage_file);
      fwrite(&hashSize, sizeof(size_t), 1, storage_file);
      fwrite(&contentSize, sizeof(size_t), 1, storage_file);

      fwrite(user.username.c_str(), sizeof(char), userSize, storage_file);
      fwrite(user.salt.data(), sizeof(uint8_t), saltSize, storage_file);
      fwrite(user.pass_hash.data(), sizeof(uint8_t), hashSize, storage_file);
      if (contentSize > 0)
        fwrite(user.content.data(), sizeof(uint8_t), contentSize, storage_file);
      bytesUsed = user.username.size() + user.salt.size() + user.pass_hash.size() + user.content.size();

    };

    //call lambda
    this->auth_table->do_all_readonly(lambdaF, []() {});

    //padding
    int pad = 8 - (bytesUsed % 8);
    while (pad != 0)
    {
      padding.push_back('\0');
      --pad;
    }
    //write the padding
    fwrite(padding.data(), sizeof(uint8_t), padding.size(), storage_file);

    if (rename(tempFileName.c_str(), currentFileName.c_str()) != 0)
    {
      string msg = "File could not be renamed";
      cout << msg << endl;
      return result_t{false, msg, {}};
    }
    fclose(storage_file);
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
  virtual result_t load_file()
  {
    //clear the tables first
    this->auth_table->clear();
    FILE *storage_file = fopen(filename.c_str(), "rb");
    size_t fileSize;
    //char *buffer;
    //size_t data;

    if (storage_file == nullptr)
    {
      return {true, "File not found: " + filename, {}};
    }
    //cout<<"user_len"<<endl;

    fseek(storage_file, 0, SEEK_END);
    fileSize = ftell(storage_file);
    rewind(storage_file);

    vector<uint8_t> buffer(fileSize);
    unsigned data = fread(buffer.data(), sizeof(char), fileSize, storage_file);

    if (data != fileSize)
    {
      return {false, "Incorrect number of bytes read from ", {}};
    }
    //cout<<fileSize<<endl;
    //cout<<data<<endl;
    unsigned int offset = 0;
    string user, salt, pass, profile;
    //const int user_len, salt_len, pass_len, profile_len;
    while (offset < buffer.size())
    {
      //len username, len salt, len pass, len profile

      //authauth
      offset += 8;

      // Read length of username
      uint8_t user_len; //if the username is too many bytes
      memcpy(&user_len, buffer.data() + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t);
      //read length of salt
      uint8_t salt_len;
      memcpy(&salt_len, buffer.data() + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t); //update offset
      // Read length of paswword

      uint8_t pass_len;
      memcpy(&pass_len, buffer.data() + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t); //update offset

      // Read length of content
      uint8_t content_len;
      memcpy(&content_len, buffer.data() + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t); //update offset

      // Read username
      //memcpy(&user, buffer.data() + offset, user_len);
      string username(buffer.begin() + offset, buffer.begin() + offset + user_len);
      offset += user_len; //update offset to say we read this much of the file
      //cout<<user_len<<endl;

      // Read salt
      string salt(buffer.begin() + offset, buffer.begin() + offset + salt_len);
      offset += salt_len; //update offset to say we read this much of the file
      //cout<<salt_len<<endl;

      // Read pass
      //cout<<fileSize<<endl;
      //cout<<offset<<endl;
      //cout<<pass_len<<endl;
      string pass(buffer.begin() + offset, buffer.begin() + offset + pass_len);
      offset += pass_len; //update offset to say we read this much of the file

      // Read profile
      string profile(buffer.begin() + offset, buffer.begin() + offset + content_len);
      offset += content_len; //update offset to say we read this much of the file

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

      //offset += sizeof(AUTHENTRY);
    }

    //cout << "my_storage.cc::save_file() is not implemented\n";
    //return result_t{false, RES_ERR_UNIMPLEMENTED, {}};
    //free (buffer);
    fclose(storage_file);
    return result_t{true, "Loaded: " + filename, {}};
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
                         const std::string &admin)
{
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
