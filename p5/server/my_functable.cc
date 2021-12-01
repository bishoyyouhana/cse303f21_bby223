#include <atomic>
#include <cassert>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/file.h"
#include "../common/protocol.h"

#include "functable.h"
#include "functypes.h"

using namespace std;

/// func_table is a table that stores functions that have been registered with
/// our server, so that they can be invoked by clients on the key/value pairs in
/// kv_store.
class my_functable : public FuncTable {
// create a map of strings to store mrname
struct func {
  map_func map;
  reduce_func reduce;
  void* handle;
};
unordered_map<std::string, func> umap;

public:
  /// Construct a function table for storing registered functions
  my_functable() {}

  /// Destruct a function table
  virtual ~my_functable() {}

  /// Register the map() and reduce() functions from the provided .so, and
  /// associate them with the provided name.
  ///
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  ///
  /// @return a status message
  virtual std::string register_mr(const std::string &mrname,
                                  const std::vector<uint8_t> &so) {
    //cout << "my_functable.cc::register_mr() not implemented\n";
    
    // check the map and see if mrname is already registered.
    // https://stackoverflow.com/questions/22880431/iterate-through-unordered-map-c
    for (const auto & [ key, value ] : umap) {
      if (key.compare(mrname)==0)
        return RES_ERR_FUNC;
    }
    // name temp file
    std::string temps = SO_PREFIX + "/" + mrname;
    const char* temp = temps.c_str();
    // fill file with content of so
    write_file(temp, so, 0);
    // now check so content?
    auto handle = dlopen(temp, RTLD_LAZY);
    // now check if map and reduce symbol exist?
    if (dlsym(handle, MAP_FUNC_NAME.c_str())==NULL) {// map doesn't exist
      dlclose(handle);
      return RES_ERR_SO;
    }
    if (dlsym(handle, REDUCE_FUNC_NAME.c_str())==NULL) {// map doesn't exist
      dlclose(handle);
      return RES_ERR_SO;
    }
    // make a func struct
    func funky;
    funky.map = (map_func) dlsym(handle, MAP_FUNC_NAME.c_str());
    funky.reduce = (reduce_func) dlsym(handle, REDUCE_FUNC_NAME.c_str());
    funky.handle = handle;
    // now put func into map
    umap.emplace(mrname, funky);
    return RES_OK;
  }

  /// Get the (already-registered) map() and reduce() functions associated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @return A pair of function pointers, or {nullptr, nullptr} on error
  virtual std::pair<map_func, reduce_func> get_mr(const std::string &mrname) {
    //cout << "my_functable.cc::get_mr() not implemented\n";

    // NB: This assert is to prevent compiler warnings.  You can remove them
    //     once the method is implemented.

    // search through map to find name
    for (const auto & [ key, value] : umap) {
      if (key.compare(mrname)==0) { // key is found, return pointers
        return {value.map, value.reduce};
      }
    }
    // no mrname in map, return error

    return {nullptr, nullptr};
  }

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  virtual void shutdown() {
    // dlclose here
    // dclose all handles and clear map
    for (const auto & [ key, value] : umap)
      dlclose(value.handle);
    umap.clear();
    //cout << "my_functable.cc::shutdown() not implemented\n";
  }
};

/// Create a FuncTable
FuncTable *functable_factory() { return new my_functable(); };