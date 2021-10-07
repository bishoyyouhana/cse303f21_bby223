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
  // create a queue of socket descriptors
  std::queue<int> socketQueue;
  // make an array of threads :D
  std::thread *pool;
  // also make a lock for the queue
  std::mutex lock;
  // make a global var to check active or not
  std::atomic<bool> active;
  // create condition variable
  std::condition_variable cv;
  // variable to get number of threads
  std::atomic<int> numThreads;
  // function to do when main thread wants to shutdown
  function<void()> shutdownTask = [](){};
  // function to do when when the thread needs to handle something
  function<bool(int)> hand;
public:
  
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) : numThreads(size),hand(handler) {
    // construct  a pool
    pool = new std::thread[size];
    // populate the pool with threads 
    for (int i = 0; i < size; i++) {
      std::lock_guard<std::mutex> sync(lock);
      pool[i] = std::thread([&](){ useHandler(); });
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
    // save function and call it in handler
    shutdownTask = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    return active;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    // wake all threads up
    lock.lock();
    cv.notify_all();
    lock.unlock();
    // join the threads 
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
    if (check_active()) { // if there is no shutdown coming
      std::lock_guard<std::mutex> sync(lock);
      socketQueue.push(sd);
      // signal the waiting threads to new signal
      cv.notify_one();
    }
  }

  /// new function to use handler
  /// makes the thread wait if there are no processes to capture
  /// If there are sd in the queue, handle them and do shutdown if necessary
  virtual void useHandler() {
    std::atomic<int> sd = 0;
    while(true) {
      // lock the queue
      std::unique_lock<std::mutex> lk(lock);
      // if shutdown, do shutdown :)
      if (active == false)
        break;
      if (socketQueue.empty()) { // no sd in the queue
        // wait https://en.cppreference.com/w/cpp/thread/condition_variable/wait
        cv.wait(lk);
      }
      else if (!socketQueue.empty()) { // there are sd
        // get the sd at the front of queue
        sd = socketQueue.front();
        socketQueue.pop();
        bool handled = hand(sd);
        if (handled == true) { // shutdown activated
          active = false;
          // set shutdown handle
          shutdownTask();
        }
        close(sd);
      }
      lk.unlock();
    }
  }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  return new my_pool(size, handler);
}
