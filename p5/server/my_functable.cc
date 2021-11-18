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
    cout << "my_functable.cc::register_mr() not implemented\n";

    // NB: These asserts are to prevent compiler warnings.  You can remove them
    //     once the method is implemented.
    assert(mrname.length() > 0);
    assert(so.size() > 0);

    return RES_ERR_UNIMPLEMENTED;
  }

  /// Get the (already-registered) map() and reduce() functions associated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @return A pair of function pointers, or {nullptr, nullptr} on error
  virtual std::pair<map_func, reduce_func> get_mr(const std::string &mrname) {
    cout << "my_functable.cc::get_mr() not implemented\n";

    // NB: This assert is to prevent compiler warnings.  You can remove them
    //     once the method is implemented.
    assert(mrname.length() > 0);

    return {nullptr, nullptr};
  }

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  virtual void shutdown() {
    cout << "my_functable.cc::shutdown() not implemented\n";
  }
};

/// Create a FuncTable
FuncTable *functable_factory() { return new my_functable(); };