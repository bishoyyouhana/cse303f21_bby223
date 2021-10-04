#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"

/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {
  struct bucket_t {
    std::list<std::pair<K, V>> entries;
    std::mutex lock;
  };
  size_t numbuckets;
  std::vector<bucket_t*> bigBuckets;
  //std::vector<Maps> bigMap;
  // std::vector<SmallM> bigMap;
public:
  /// Construct by specifying the number of buckets it should have
  ///
  /// @param _buckets The number of buckets
  ConcurrentHashMap(size_t _buckets) : numbuckets(_buckets)
  {
<<<<<<< HEAD
    // std::cout << "ConcurrentHashMap::ConcurrentHashMap() is not implemented";
=======
    //std::cout << "ConcurrentHashMap::ConcurrentHashMap() is not implemented";
>>>>>>> d56029cfb08c03030a8424dba07f1020ab695658
    for (size_t i = 0; i < _buckets; i++) {
      // bucket_t* bucket = new bucket_t;
      // struct SmallM littleMap;
      //bucket.
      bigBuckets.emplace_back(new bucket_t());
    } 
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() {
    /*
    * Use the clear function to destroy the map
    * Also free the space by deallocating the map.
    */
    clear();
    for(size_t i = 0; i < numbuckets; i++)
      delete bigBuckets.at(i);
    //std::cout << "ConcurrentHashMap::~ConcurrentHashMap() is not implemented";
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    // lock with mutex
    for(size_t i = 0; i < numbuckets; i++)
      bigBuckets.at(i)->lock.lock();
    // clear each list per bucket
    for(size_t i = 0; i < numbuckets; i++)
      bigBuckets.at(i)->entries.clear(); 
    // unlock with mutex
    for(size_t i = 0; i < numbuckets; i++)
      bigBuckets.at(i)->lock.unlock();

    // std::cout << "ConcurrentHashMap::clear() is not implemented";
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    // std::cout << "ConcurrentHashMap::insert() is not implemented";
    // https://stackoverflow.com/questions/22269435/how-to-iterate-through-a-list-of-objects-in-c
    // find what bucket to put key and value in
    size_t bucket = std::hash<K>{}(key) % numbuckets;
    // lock the bucket using a guard
    const std::lock_guard<std::mutex> lock(bigBuckets.at(bucket)->lock);
    // iterate through the list to find if there is matching key
    for (auto it = bigBuckets.at(bucket)->entries.begin(); it != bigBuckets.at(bucket)->entries.end(); ++it) {
      if (it->first == key) {
        // there is a matching key so don't insert
        return false;
      }
    } 
    // insert key and value into list and fun on_success
    bigBuckets.at(bucket)->entries.emplace(bigBuckets.at(bucket)->entries.begin(), key, val);
    on_success();
    // unlock and return true as insert was sucessfull
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    // std::cout << "ConcurrentHashMap::upsert() is not implemented";
    // Iterate through the list, and check the key value. If it matches with K, then replace the map
    // find what bucket to put key and value in
    size_t bucket = std::hash<K>{}(key) % numbuckets;
    // lock the bucket using a guard
    const std::lock_guard<std::mutex> lock(bigBuckets.at(bucket)->lock);
    for (auto it = bigBuckets.at(bucket)->entries.begin(); it != bigBuckets.at(bucket)->entries.end(); ++it) {
      if (it->first == key) {
        // matching key found, update new value and return
        it->second = val;
        on_upd();
        return false; 
      }
    } 
    // else insert values as per usual
    on_ins();
    bigBuckets.at(bucket)->entries.emplace(bigBuckets.at(bucket)->entries.begin(), key, val); 
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    // std::cout << "ConcurrentHashMap::do_with() is not implemented";
    // Iterate through the list, and check the key value. If it matches with K, then do function
    // find what bucket to put key and value in
    size_t bucket = std::hash<K>{}(key) % numbuckets;
    // lock the bucket using a guard
    const std::lock_guard<std::mutex> lock(bigBuckets.at(bucket)->lock);
    for (auto it = bigBuckets.at(bucket)->entries.begin(); it != bigBuckets.at(bucket)->entries.end(); ++it) {
      if (it->first == key) {
        // apply function on value
        f(it->second);
        return true;
      }
    } 
    return false; // key did not exist
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    // std::cout << "ConcurrentHashMap::do_with_readonly() is not implemented";
    // Iterate through the list, and check the key value. If it matches with K, then do function
    // find what bucket to put key and value in
    size_t bucket = std::hash<K>{}(key) % numbuckets;
    // lock the bucket using a guard
    const std::lock_guard<std::mutex> lock(bigBuckets.at(bucket)->lock);
    for (auto it = bigBuckets.at(bucket)->entries.begin(); it != bigBuckets.at(bucket)->entries.end(); ++it) {
      if (it->first == key) {
        // apply function to value
        f(it->second);
        return true;
      }
    } 
    return false; // key did not exist
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
    // std::cout << "ConcurrentHashMap::remove() is not implemented";
    // find what bucket to put key and value in
    size_t bucket = std::hash<K>{}(key) % numbuckets;
    // lock the bucket using a guard
    const std::lock_guard<std::mutex> lock(bigBuckets.at(bucket)->lock);
    for (auto it=bigBuckets.at(bucket)->entries.begin(); it!=bigBuckets.at(bucket)->entries.end(); it++) {
      if (it->first == key) {
        // if key is found, erase the key and value
        bigBuckets.at(bucket)->entries.erase(it);
        on_success();
        return true;
      }
    } // no matched key 
    return false;
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
    // std::cout << "ConcurrentHashMap::do_all_readonly() is not implemented";
    // lock with mutex
    for(size_t i = 0; i < numbuckets; i++)
      bigBuckets.at(i)->lock.lock();
     // Iterate through the list, and check the key value. If it matches with K, then do function
    for(size_t i = 0; i < numbuckets; i++) {
      for (auto it = bigBuckets.at(i)->entries.begin(); it != bigBuckets.at(i)->entries.end(); ++it) {
        f(it->first, it->second);
      }
    }
    // apply before unlock and after function apply
    then(); 
    // unlock with mutex
    for(size_t i = 0; i < numbuckets; i++)
      bigBuckets.at(i)->lock.unlock();
  }
};
