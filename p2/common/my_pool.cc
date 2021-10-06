#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

class my_pool : public thread_pool {
  // create place holders for pool and queue
  // make an array of threads :D
  std::queue<int> socketQueue;
  // if ( socketQueue.empty()) {};
  std::thread *pool;
  // also make a lock for the queue
  std::mutex lock;
  // make a global var to check active or not
  std::atomic<bool> active;
  // create condition variable
  std::condition_variable cv;
  // variable to get number of threads
  std::atomic<int> numThreads;
public:
  
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) : numThreads(size) {
    // lock to make the thread pool
    // lock.lock();
    // construct  a pool
    std::thread *pool[size];
    // make the handler lambda to be used by thread
    auto func = [&]() { useHandler(handler); };
    // need to construct queue of ints for sockets
    for (int i = 0; i < size; i++) {
      pool[i] = new std::thread(func);
    }
    // constructed thread pool is active
    active = true;
  }

  /// destruct a thread pool
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    //cout << "my_pool::set_shutdown_handler() is not implemented";
    // shutdown each thread, this should be empty as there is no shutdown handler yet
    // apply the function
    func();
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    // cout << "my_pool::check_active() is not implemented";
    return active;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    // cout << "my_pool::await_shutdown() is not implemented";
    // check if all of the threads are waiting.
    // if they are, commence shutdown
    for (int i = 0; i < numThreads; i++) {
      pool[i].join();
    }
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    // pass the sd into queue, waiting threads will wake and grab sd
    // send a signal to thread pool
    // cout << "my_pool::service_connection() is not implemented";
    if (check_active()) { // if there is no shutdown coming
      std::lock_guard<std::mutex> sync(lock);
      socketQueue.push(sd);
    }
    // signal all of the waiting threads to new signal
    cv.notify_all();
  }

  // new function to use handler
  virtual void useHandler(function<bool(int)> handler) {
    std::atomic<int> sd = 0;
    while(true) {
      // lock the queue
      std::unique_lock<std::mutex> lk(lock);
      if (socketQueue.empty()) { // no sd in the queue
        // wait https://en.cppreference.com/w/cpp/thread/condition_variable/wait
        cv.wait(lk);
        continue;
      }
      else if (!socketQueue.empty()) { // there are sd
        // get the sd at the front of queue
        sd = socketQueue.front();
        socketQueue.pop();
        break;
      }
    }
    // now use handler as you have sd
    bool handled = handler(sd);
    if (handled == false) {
      // then there is no need to shutdown
    }
    else {
      // do shutdown
      // change active to false
      active = false;
      // set shutdown handle
      auto lambda = [](){};
      set_shutdown_handler(lambda);
      // can't let the main thread accept anymore sd
      // then wait for rest of thread to finish processes 
      while (!socketQueue.empty()) {
        std::unique_lock<std::mutex> lk(lock);
        
      }
      // delete the queue and make sure all threads are waiting
    }
  }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  return new my_pool(size, handler);
}
