/ ============================================================
public:
    PulseManager(RemoteQuorumClock& clock)
        : clock_(clock)
    {}

    void start()
    {
        running_ = true;
        thread_ = std::thread([this]() { loop(); });
    }

    void stop()
    {
        running_ = false;
        if (thread_.joinable())
            thread_.join();
    }

    TemporalState current_state() const
    {
        return tsm_.state();
    }

private:
    void loop()
    {
        while (running_) {
            try {
                clock_.now_unix();
                last_success_ = now_ms();
            } catch (...) {
                // ignore, state will degrade
            }

            uint64_t delta = now_ms() - last_success_;
            tsm_.update(delta);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    uint64_t now_ms() const
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    RemoteQuorumClock& clock_;
    TemporalStateMachine tsm_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    uint64_t last_success_{0};
};

} // namespace uml001