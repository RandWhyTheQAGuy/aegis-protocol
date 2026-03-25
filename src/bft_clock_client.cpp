#include "uml001/core/bft_clock_client.h"
#include "uml001/crypto/crypto_utils.h"

#include <iostream>

namespace uml001 {

BftTimeResponseData BftClockClient::do_grpc_request() const {
    quorumtime::TimeRequest request;

    std::string request_id = generate_random_bytes_hex(16);

    request.set_client_id(cfg_.client_id);
    request.set_request_id(request_id);

    quorumtime::TimeResponse response;
    grpc::ClientContext ctx;

    ctx.set_deadline(
        std::chrono::system_clock::now() +
        std::chrono::milliseconds(cfg_.connect_timeout_ms));

    auto status = stub_->GetQuorumTime(&ctx, request, &response);
    if (!status.ok()) {
        throw BftClockIpcError(status.error_message());
    }

    if (response.request_id() != request_id) {
        throw BftClockIpcError("Replay attack detected");
    }

    BftTimeResponseData r;
    r.unix_time_ms        = response.unix_time_ms();
    r.confidence_interval = response.confidence_interval_ms();
    r.active_nodes        = response.active_nodes();
    r.projected_drift_ppm = response.projected_drift_ppm();

    return r;
}

uint64_t BftClockClient::now_unix() const {
    std::lock_guard<std::mutex> lock(mx_);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - cache_filled_).count();
    
    if (elapsed > static_cast<int64_t>(cfg_.cache_ttl_ms) || cached_unix_time_s_ == 0) {
        auto response = do_grpc_request();
        verify_skew(response);
        enforce_monotonic(response.unix_time_ms / 1000);
        
        cached_unix_time_s_ = response.unix_time_ms / 1000;
        cached_sync_unix_s_ = cached_unix_time_s_;
        cached_confidence_ms_ = response.confidence_interval;
        cached_active_nodes_ = response.active_nodes;
        cached_drift_ppm_ = response.projected_drift_ppm;
        cache_filled_ = now;
    }
    
    return cached_unix_time_s_;
}

uint64_t BftClockClient::now_ms() const {
    return now_unix() * 1000ULL;
}

bool BftClockClient::is_synchronized() const {
    return status() == ClockStatus::SYNCHRONIZED;
}

uint64_t BftClockClient::last_sync_unix() const {
    std::lock_guard<std::mutex> lock(mx_);
    return cached_sync_unix_s_;
}

ClockStatus BftClockClient::status() const {
    std::lock_guard<std::mutex> lock(mx_);
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - cache_filled_).count();
    
    if (elapsed > static_cast<int64_t>(cfg_.cache_ttl_ms) || cached_unix_time_s_ == 0) {
        return ClockStatus::UNKNOWN;
    }
    
    if (cached_confidence_ms_ < 50.0 && cached_drift_ppm_ < 100.0) {
        return ClockStatus::SYNCHRONIZED;
    } else if (cached_confidence_ms_ < 200.0) {
        return ClockStatus::DEGRADED;
    } else {
        return ClockStatus::UNTRUSTED;
    }
}

void BftClockClient::verify_skew(const BftTimeResponseData& r) const {
    // Use now_unix() for time instead of std::chrono
    uint64_t local_now = now_unix();
    
    uint64_t remote_time_s = r.unix_time_ms / 1000;
    uint64_t skew = (local_now > remote_time_s) ? 
        (local_now - remote_time_s) : (remote_time_s - local_now);
    
    if (skew > cfg_.max_skew_s) {
        throw BftClockIpcError("Clock skew exceeds safety threshold: " + 
                              std::to_string(skew) + "s > " + 
                              std::to_string(cfg_.max_skew_s) + "s");
    }
}

void BftClockClient::enforce_monotonic(uint64_t new_time) const {
    uint64_t current_floor = monotonic_floor_.load();
    if (new_time < current_floor) {
        throw BftClockIpcError("Monotonic violation detected: " + 
                              std::to_string(new_time) + " < " + 
                              std::to_string(current_floor));
    }
    monotonic_floor_.store(new_time);
}

} // namespace uml001