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

  //virtual result_t auth(const string, const string );

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  /// Helper function that simplifies hashing
  ///
  /// @param pass   given password in string format
  /// @param salt   salt in vector fomrat
  /// @return hash   hash result

  virtual vector<uint8_t> hash_pass(string pass, vector<uint8_t> &salt)
  {
    //cout << "hello in hash_pass" <<endl;
    vector<uint8_t> toHash;
    vector<uint8_t> password;
    vector<uint8_t> saltVec;

    //cout << salt.size()<<endl;

    password.insert(password.begin(), pass.begin(), pass.end());
        //cout << password.size()<<endl;

    toHash.insert(toHash.begin(), password.begin(), password.end());
    toHash.insert(toHash.end(), salt.begin(), salt.end());

    //cout << toHash.size()<<endl;

    vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, toHash.data(), toHash.size());
    SHA256_Final(hash.data(), &sha256);

    //cout << hash.size()<<endl; 

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
    //cout << "my_storage.cc::add_user() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    vector<uint8_t> saltVec(LEN_SALT);
    //vector<uint8_t> content;
    //unsigned char salt[LEN_SALT];
    AuthTableEntry new_user;                      //user we will add
    int success = RAND_bytes(saltVec.data(), LEN_SALT); //salt

    //uint8_t salt[LEN_SALT];
    //RAND_bytes(salt, LEN_SALT);
    //vector saltVec(&salt[0], &salt[LEN_SALT]); should it be len -1? 

    //string saltName(reinterpret_cast<char *>(salt));
    //saltVec.insert(saltVec.begin(), saltName.begin(), saltName.end());

    if (success == 0)
    {
      return {false, RES_ERR_SERVER, {}};
    }

    //involved a lot of coding before the helper function was created
    vector<uint8_t> hashedPass = hash_pass(pass, saltVec);

    //cout << "add user called 1"<<endl;
    //cout << saltVec.data()<<endl;

    //inserting user
    new_user.username = user;
    //new_user.username.insert(new_user.username.begin(), user.begin(), user.end());
    new_user.salt= saltVec;
    //new_user.salt.insert(new_user.salt.begin(), saltVec.begin(), saltVec.end());

    //new_user.content.insert(new_user.content.begin(), content.begin(), content.end());
    new_user.pass_hash= hashedPass;

    bool check = auth_table->insert(user, new_user, []() {});

    //cout << hashedPass.size()<<endl;

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
                                 const vector<uint8_t> &content)
  {
    //cout << "my_storage.cc::set_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings

    auto allow = auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)
    {
      return result_t{false, RES_ERR_LOGIN, {}};
    }

    auto lambdaF = [&](AuthTableEntry &user)
    {
      if(content.size()>0) user.content = content;
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
    this->auth_table->do_with_readonly(who, lamdaf);
    if (content.size()==0)
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

    //assert(user.length() > 0);
    //assert(pass.length() > 0);
    allUsers.pop_back();
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
    vector<uint8_t> hashPass(LEN_PASSHASH);//LEN_PASSWORD
    vector<uint8_t> saltVec(LEN_SALT);

    //retrieving necessary data
    auto lamdaF = [&](const AuthTableEntry &tmpuser)
    {
      //if((auth_table->do_with_readonly(user, [&](const AuthTableEntry& tmpUser){
      authUser = tmpuser.username;
      //saltVec.insert(saltVec.begin(), tmpuser.salt.begin(), tmpuser.salt.end());
      saltVec = tmpuser.salt;
      //cout<< "help me pls"<<endl;
      //cout<< tmpuser.salt.data()<<endl;
      hashPass = tmpuser.pass_hash;
    };
    this->auth_table->do_with_readonly(user, lamdaF);

    vector<uint8_t> passVec = hash_pass(pass, saltVec);

    //cout<<saltVec.size()<<endl;
    
    //cout<<hashPass.size()<<endl;
    //cout<<pass<<endl;
    //cout<<user<<endl;

    if (passVec == hashPass) //will this work?
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
  { 
    string currentFileName = this->filename;
    string tempFileName = this->filename + ".tmp";
    FILE *storage_file = fopen(tempFileName.c_str(), "wb");

    vector<uint8_t> AUTHEN(8);
    //new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
    AUTHEN.insert(AUTHEN.begin(),AUTHENTRY.begin(), AUTHENTRY.end());


    auth_table->do_all_readonly ([&](string , const AuthTableEntry table) {

      char padding = '\0';
      int bytesUsed=0;
      fwrite(AUTHEN.data(), sizeof(char), AUTHENTRY.length(), storage_file);

      size_t userSize = table.username.length();
      size_t saltSize = table.salt.size();
      size_t hashSize = table.pass_hash.size();
      size_t contentSize = table.content.size();

      /*
      cout<<"savefile"<<endl;  

      cout<<userSize<<endl;
      cout<<saltSize<<endl;
      cout<<hashSize<<endl;
      cout<<contentSize<<endl;
      cout<<table.username.c_str()<<endl;
      cout<<table.salt.data()<<endl;
      cout<<table.pass_hash.data()<<endl;
      //cout<<table.content.data()<<endl;
*/

      fwrite(&userSize, sizeof(size_t), 1, storage_file);
      fwrite(&saltSize, sizeof(size_t), 1, storage_file);
      fwrite(&hashSize, sizeof(size_t), 1, storage_file);
      fwrite(&contentSize, sizeof(size_t), 1, storage_file);

      vector<uint8_t> usernameVec(userSize);
      usernameVec.insert(usernameVec.begin(), table.username.begin(), table.username.end());
      bytesUsed += fwrite(usernameVec.data(),sizeof(char), userSize, storage_file );

      //bytesUsed += fwrite(table.username.c_str(), sizeof(char), userSize, storage_file);
      bytesUsed+= fwrite(table.salt.data(), sizeof(uint8_t), saltSize, storage_file);
      bytesUsed += fwrite(table.pass_hash.data(), sizeof(uint8_t), hashSize, storage_file);

      if (contentSize > 0) bytesUsed += fwrite(table.content.data(), sizeof(uint8_t), contentSize, storage_file);
      //int x = fwrite(&padding, sizeof(char), 8, storage_file);
      if((bytesUsed%8) >0) fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);
      //cout<<bytesUsed<<endl;
    
    },[](){});
    
  rename(tempFileName.c_str(), currentFileName.c_str());
    fclose(storage_file);
    return result_t{true, RES_OK, {}};
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
   //cout<<"entered load file"<<endl;
    FILE *storage_file = fopen(filename.c_str(), "rb");
    if (storage_file == nullptr)  return {true, "File not found: " + filename, {}};
    this->auth_table->clear();

    size_t userLen, saltLen, passLen, dataLen;
    //string auth="";
    //string buffer="";
    //auth.resize(8);
    //buffer.resize(8);
    int bytesUsed=0;
    bool cont = true;

    vector<uint8_t> AUTHEN(8);
    //new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
    AUTHEN.insert(AUTHEN.begin(),AUTHENTRY.begin(), AUTHENTRY.end());

    //AuthTableEntry new_user;
    vector<uint8_t> auth(8);
    fread(auth.data(),sizeof(char), 8, storage_file );

    //if(auth.compare(AUTHENTRY) != 0) cont = false;
    //cout<<cont<<endl;
    //cout<<auth<<endl;
    
   
  
    int x;
    int i=0;
    while(cont){
      AuthTableEntry new_user;
      bytesUsed =0;
      //cout<<"load"<<endl;
      fread(&userLen,sizeof(size_t), 1, storage_file );
      fread(&saltLen,sizeof(size_t), 1, storage_file );
      fread(&passLen,sizeof(size_t), 1, storage_file );
      fread(&dataLen,sizeof(size_t), 1, storage_file );

      //usernameVec.reserve(userLen);

      vector<uint8_t> usernameVec(userLen);
      bytesUsed += fread(usernameVec.data(),sizeof(char), userLen, storage_file );
      new_user.username.insert(new_user.username.begin(), usernameVec.begin(), usernameVec.end());
      
      //cout<< new_user.username.length()<<endl;
      //cout<<"user: ";
      //cout<< usernameVec.size()<<endl;
      //cout<<x<<endl;

      vector<uint8_t> saltVec(saltLen);
      bytesUsed +=fread(saltVec.data(), sizeof(uint8_t), saltLen, storage_file );
      new_user.salt.insert(new_user.salt.begin(), saltVec.begin(), saltVec.end());

      //cout<< new_user.salt.size()<<endl;
      //cout<<"salt: ";
      //cout<< saltVec.size()<<endl;
      //cout<<x<<endl;

      vector<uint8_t> passVec(passLen);
      bytesUsed +=fread(passVec.data(),sizeof(uint8_t), passLen, storage_file );
      new_user.pass_hash.insert(new_user.pass_hash.begin(), passVec.begin(), passVec.end());

      //cout<< new_user.pass_hash.size()<<endl;
      //cout<<"pass_hash: ";
      //cout<< passVec.size()<<endl;
      //cout<<x<<endl;

      vector<uint8_t> profVec(dataLen);
      if(dataLen>0){   
        bytesUsed +=fread(profVec.data(), sizeof(uint8_t), dataLen, storage_file );
        new_user.content.insert(new_user.content.begin(), profVec.begin(), profVec.end());
      }else{
        new_user.content.reserve(0);
      }

      //cout<< new_user.content.size()<<endl;
      //cout<<"content: ";
      //cout<< profVec.size()<<endl;
      //cout<<x<<endl;

      vector<uint8_t> buffer(8);
      //buffer.clear();
      if((bytesUsed%8)>0) fread(buffer.data(),sizeof(char), (8-bytesUsed%8), storage_file);
      //fread(&auth[0],sizeof(char), 8, storage_file);
      bool check = auth_table->insert(new_user.username, new_user, [&]() {});
      //cout<<"we got to here!"<<endl;
      //cout<<"loooooooooooooooooooooooooooooooop"<<endl;
      //cout<<buffer.size()<<endl;
      //cout<<buffer.data()<<endl;

      vector<uint8_t> auth(8);
      //auth.clear();
      fread(auth.data(),sizeof(char), 8, storage_file);

            //if(!(bytesUsed%8 ==0))fwrite(&padding, sizeof(char), (8-bytesUsed%8), storage_file);

      //cout<<auth.compare(AUTHENTRY)<<endl;
      if(equal(AUTHEN.begin(), AUTHEN.end(), auth.begin())) {
      cont = true;
      }else{
        cont = false;
      }
      //cout<<"loadfile"<<endl;
      //cout<<AUTHEN ==auth <<endl;
      /*
      bool result = std::equal(AUTHEN.begin(), AUTHEN.end(), auth.begin());
      cout<<result<<endl;
      cout<<cont<<endl;
      cout<<AUTHEN.data()<<endl;
      cout<<auth.data()<<endl;
      cout<<auth.size()<<endl;
*/
      
      //cout<<"-----------------------------"<<endl;      
      /*
    cout<<userLen<<endl;
      cout<<saltLen<<endl;
      cout<<passLen<<endl;
      cout<<dataLen<<endl;
      cout<<usernameVec.data()<<endl;
      cout<<usernameVec.size()<<endl;
      cout<<saltVec.data()<<endl;
      cout<<saltVec.size()<<endl;
      cout<<passVec.data()<<endl;
      cout<<passVec.size()<<endl;
      //cout<<profVec.data()<<endl;
      cout<<profVec.size()<<endl;
      cout<<bytesUsed<<endl;*/
      
      i++;
      
    }

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
