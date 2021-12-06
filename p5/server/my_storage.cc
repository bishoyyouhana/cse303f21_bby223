#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "../common/contextmanager.h"
#include "../common/protocol.h"

#include "functable.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "quotas.h"
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

  /// The name of the admin user
  string admin_name;

  /// The function table, to support executing map/reduce on the kv_store
  FuncTable *funcs;

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
            size_t rqq, double qd, size_t top, const std::string &admin)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)), admin_name(admin),
        funcs(functable_factory()) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    cout << "my_storage.cc::~MyStorage() is not implemented\n";
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
    return add_user_helper(user, pass, auth_table, storage_file);
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
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
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
    return kv_insert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
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
    return kv_get_helper(user, pass, key, auth_table, kv_store, mru, up_quota,
                         down_quota, req_quota, quota_dur, quota_table);
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
    return kv_delete_helper(user, pass, key, auth_table, kv_store, storage_file,
                            mru, up_quota, down_quota, req_quota, quota_dur,
                            quota_table);
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
    return kv_upsert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
  }; 

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    return kv_all_helper(user, pass, auth_table, kv_store, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    return kv_top_helper(user, pass, auth_table, mru, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };

  /// Register a .so with the function table
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, used to authenticate
  /// @param mrname The name to use for the registration
  /// @param so     The .so file contents to register
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t register_mr(const string &user, const string &pass,
                               const string &mrname,
                               const vector<uint8_t> &so) {
    
    if(admin_name!=user) return result_t{false, RES_ERR_LOGIN, {}};
    
    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)   return result_t{false, RES_ERR_LOGIN, {}};

    if (funcs->get_mr(mrname).first != nullptr) return result_t{false, RES_ERR_FUNC, {}};
 
    string returnValue = funcs->register_mr(mrname, so);
    return {false, returnValue, {}};
  };

  /// Helper function that runs the child process for invoke_mr 
  ///
  /// @param input_fd   fd to read data from
  /// @param output_fd  fd to write data to
  /// @param mapping    the map function to run
  /// @param reducing   the reduce function to run
  ///
  /// @return A boolean that indicates the success of the process
  bool child_process(int input_fd, int output_fd, map_func mapping, reduce_func reducing){
    vector<vector<uint8_t>> reduceInput;
    //vector<uint8_t> reduceInput;

cout<<"child"<<endl;
    //read
    while(true){ // code breaks here, infinite loop
      //key
      size_t key_len;
    
      int readBytes = read(input_fd, &key_len, sizeof(size_t));
      if (readBytes == 0) break;
cout<<key_len<<endl;
      char key[key_len];
      readBytes = read(input_fd, key, key_len);
      cout<<key<<endl;

      //value
      size_t val_len;
      readBytes = read(input_fd, &val_len, sizeof(size_t));
      if (readBytes == 0) break;
      cout<<val_len<<endl;
 
      char val[val_len];
      readBytes = read(input_fd, val, val_len);
      cout<<val<<endl;


 
      string string_key(key, key_len);
      string string_val(val, val_len);
      vector<uint8_t> val_vec;
      val_vec.insert(val_vec.begin(),string_val.begin(), string_val.end());



      vector<uint8_t> mapresult;  // got lost from this point
      mapresult = mapping(string_key, val_vec);

      reduceInput.push_back(mapresult);

      
    
      }
close(input_fd);
      vector<uint8_t> reduceResult = reducing(reduceInput);
    

    //write

    write(output_fd, reduceResult.data(), reduceResult.size());


    close(output_fd);
    return true;
  }

  /// Run a map/reduce on all the key/value tuples of the kv_store
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, to authenticate
  /// @param mrname The name of the map/reduce functions to use
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t invoke_mr(const string &user, const string &pass,
                             const string &mrname) {
    //if(admin_name!=user) return result_t{false, RES_ERR_LOGIN, {}};
    
    auto allow = this->auth(user, pass); //think about changing to tuple
    if (!allow.succeeded)   return result_t{false, RES_ERR_LOGIN, {}};
    

    std::pair<map_func, reduce_func> func_mr = funcs->get_mr(mrname);
cout<<"hello1"<<endl;
    
    //some pipes for communication
    //0 is for reading and 1 is for writing
    int parentPipe[2];
    int childPipe[2];
    if (pipe(parentPipe) == -1)  return {false, RES_ERR_SERVER, {}};
    if (pipe(childPipe) == -1)  return {false, RES_ERR_SERVER, {}};
    
    pid_t pid =fork();
    pid_t wait; 
    int status;
cout<<"hello2"<<endl;
    //start forking
    if (pid < 0) {
      return {false, RES_ERR_SERVER, {}};
    }
    else if(pid>0){ //parent process
      //lose reading end of parent pipe amd write end of child pipe
      close(parentPipe[0]);
      close(childPipe[1]);
      //vector<uint8_t> returnValue;

      //we need key and value of the key, therefore we need size 
      //format we are using: keySize, key, valueSize, val
      kv_store->do_all_readonly([&](string key, const vector<uint8_t> val) {  
        
        size_t keyLen = key.length();
        size_t valLen = val.size();
        write(parentPipe[1], &keyLen, sizeof(key.length()));
        write(parentPipe[1], key.c_str(),  key.length());
        write(parentPipe[1], &valLen, sizeof(val.size()));
        write(parentPipe[1], val.data(), val.size()); 

      }, [&]() {});

      close(parentPipe[1]);
      cout<<"hello3"<<endl;
      //wait for msg
      int status;
      if((wait = waitpid(pid, &status, WUNTRACED | WCONTINUED)) == -1){
        return {false, RES_ERR_SERVER, {}};//return server error
      }

      int status2;
      if((status2 = WIFEXITED(status))){
        if(status2 != 0) return {false, RES_ERR_SERVER, {}};
      }

      //reading from the child
      int size;
      read(childPipe[0], &size, sizeof(size_t));
cout<<"hello3"<<endl;
      vector<uint8_t> childReturn(size);
      read(childPipe[0], childReturn.data(), childReturn.size());
    close(parentPipe[0]);
    close(childPipe[1]);
    close(childPipe[0]);
    return {true, RES_OK, childReturn}; ///?????????????????????????????????????????????????????

    }else{ //child process
      //close pipe for parent write and children write
    close(parentPipe[1]);
    close(childPipe[0]);
    //use child_mr here
    if (child_process(parentPipe[0], childPipe[1], func_mr.first, func_mr.second)){
      return {true, RES_OK, {}};
	}
    else{
      //problem
      return {false, RES_ERR_SERVER, {}};
	}
    }

    return {true, RES_OK, {}};
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    fclose(storage_file);
    //cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
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
    return load_file_helper(auth_table, kv_store, filename, storage_file, mru);
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
