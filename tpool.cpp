#include "tpool.h"
#include <iostream>

ThreadPool::ThreadPool(size_t num_threads) : stop(false) {
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);

    pthread_t thread;
    for (size_t i = 0; i < num_threads; i++) {
        pthread_create(&thread, NULL, thread_func, this);
        threads.push_back(thread);
    }
}

ThreadPool::~ThreadPool() {
    std::cerr << "Destroying thread pool\n";
    stop = true; // atomic
    pthread_cond_broadcast(&cond);

    for (size_t i = 0; i < threads.size(); i++) {
        pthread_join(threads[i], NULL); 
        // blocking wait all threads to finish
        std::cerr << "Thread " << i << " joined\n";
    }

    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    std::cerr << "Thank you for using slimlix's memory-unsafe thread pool\n";
}

void ThreadPool::add_task(std::function<void()> task) {
    pthread_mutex_lock(&mutex);
    tasks.push(task);
    pthread_mutex_unlock(&mutex);
    pthread_cond_broadcast(&cond); // only main thread will add tasks
}

void *ThreadPool::thread_func(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;

    while (true) {
        pthread_mutex_lock(&pool->mutex);

        while (pool->tasks.empty() && !pool->stop) {
            pthread_cond_wait(&pool->cond, &pool->mutex); 
            // currently no task, go wait until new task is added
            // test condition with mutex locked
        }

        if (pool->stop) {
            pthread_mutex_unlock(&pool->mutex);
            pthread_exit(NULL);
        } 

        // task not empty AND stop is false
        std::function<void()> task = pool->tasks.front();
        pool->tasks.pop();

        pthread_mutex_unlock(&pool->mutex);

        task();

        // what if task > 10? add_task can broadcast to no one...
        // fine: after while it won't do wait
    }
}