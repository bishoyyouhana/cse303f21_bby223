#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {

std::deque<std::string> mru;
size_t numTrack;

public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) : numTrack(elements) {}

  /// Destruct the mru_manager
  virtual ~my_mru() {
    mru.clear();
  }

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
    // do linear search, which is O(n)
    // also check size of deque to see if not past numTrack
    for(auto it = mru.begin(); it != mru.end(); it++) {
      if ((*it).compare(elt) == 0) {
        mru.erase(it);
        break;
      }
    }
    if (mru.size() == numTrack) // if all ready at max size, then erase head
      mru.erase(mru.begin());
    mru.emplace_back(elt);
  }

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {
    // do linear search, if element is there remove
    for(auto it = mru.begin(); it != mru.end(); it++) {
      if ((*it).compare(elt) == 0) {
        mru.erase(it);
        break;
      }

    }
  }

  /// Clear the mru_manager
  virtual void clear() {
    mru.clear();
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() {
    // create a final string
    std::string result = "";
    // loop throug mru and add string value from tail (recently used).
     for(auto it = mru.end()-1; it != mru.begin(); it--) {
       result = result + (*it) + "\n";
     }
     // print head of deque
     result = result + mru.at(0) + "\n";
     return result;
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }