#ifndef TPOOL_H
#define TPOOL_H

#include <pthread.h>
#include <unistd.h>
#include <queue>
#include <atomic>
#include <functional>

class ThreadPool {

  public:
    ThreadPool(size_t num_threads);
    ~ThreadPool();

    // add a task to the pool
    void add_task(std::function<void()> task);
  private:
    std::vector<pthread_t> threads; // explicitly join threads
    std::queue<std::function<void()>> tasks;
    std::atomic<bool> stop;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    static void *thread_func(void *arg);

};
#endif // TPOOL_H