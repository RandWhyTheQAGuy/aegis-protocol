#include <thread>
#include <atomic>
#include <chrono>
#include "uml001/core/remote_quorum_clock.h"

namespace uml001 {

class QuorumPulseManager {
public:
    QuorumPulseManager(const std::string& endpoint)
        : clock_(endpoint), running_(true) {}

    void start() {
        thread_ = std::thread([this]() {
            while (running_) {
                try {
                    last_time_ = clock_.get_time_ms();
                    last_update_ = std::chrono::steady_clock::now();
                } catch (...) {
                    // ignore, handled by TSLQ
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
    }

    double get_tslq_seconds() {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - last_update_).count();
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

private:
    RemoteQuorumClock clock_;
    std::thread thread_;
    std::atomic<bool> running_;

    int64_t last_time_;
    std::chrono::steady_clock::time_point last_update_;
};

}