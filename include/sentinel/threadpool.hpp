#pragma once
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace sentinel {

// Minimal fixed-size thread pool. wait_idle() blocks until all submitted work is done.
class ThreadPool {
public:
    explicit ThreadPool(std::size_t n) {
        if (n == 0) n = 1;
        for (std::size_t i = 0; i < n; ++i) workers_.emplace_back([this] { run(); });
    }
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ~ThreadPool() {
        {
            std::lock_guard lk(m_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_) t.join();
    }

    void submit(std::function<void()> job) {
        {
            std::lock_guard lk(m_);
            jobs_.push(std::move(job));
            ++pending_;
        }
        cv_.notify_one();
    }

    void wait_idle() {
        std::unique_lock lk(m_);
        idle_cv_.wait(lk, [this] { return pending_ == 0; });
    }

private:
    void run() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock lk(m_);
                cv_.wait(lk, [this] { return stop_ || !jobs_.empty(); });
                if (jobs_.empty()) return;  // stop_ and drained
                job = std::move(jobs_.front());
                jobs_.pop();
            }
            try { job(); } catch (...) {}
            {
                std::lock_guard lk(m_);
                --pending_;
            }
            idle_cv_.notify_all();
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> jobs_;
    std::mutex m_;
    std::condition_variable cv_, idle_cv_;
    std::size_t pending_ = 0;
    bool stop_ = false;
};

}  // namespace sentinel
