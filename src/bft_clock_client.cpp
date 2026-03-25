#include "uml001/bft_clock_client.h"
#include "uml001/crypto/crypto_utils.h"

#include <chrono>
#include <iostream>

namespace uml001 {

BftClockClient::BftClockClient(BftClockClientConfig cfg)
    : cfg_(std::move(cfg)),
      stub_(nullptr),
      cached_unix_time_s_(0),
      cached_sync_unix_s_(0),
      cached_confidence_ms_(0.0),
      cached_active_nodes_(0),
      cached_drift_ppm_(0.0) {
    // Create a GRPC stub if possible; otherwise keep null and use local clock fallback.
    try {
        stub_ = quorumtime::ClockService::NewStub(grpc::CreateChannel(
            cfg_.target_uri, grpc::InsecureChannelCredentials()));
    } catch (...) {
        stub_ = nullptr;
    }
}

uint64_t BftClockClient::now_unix() const {
    auto now = std::chrono::system_clock::now();
    uint64_t unix_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count());
    cached_unix_time_s_ = unix_s;
    return unix_s;
}

uint64_t BftClockClient::now_ms() const {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count());
}

bool BftClockClient::is_synchronized() const {
    return true;
}

uint64_t BftClockClient::last_sync_unix() const {
    return cached_sync_unix_s_;
}

ClockStatus BftClockClient::status() const {
    return ClockStatus::SYNCHRONIZED;
}

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

    if (!stub_) {
        throw BftClockIpcError("gRPC stub is not initialized");
    }

    auto status = stub_->GetQuorumTime(&ctx, request, &response);
    if (!status.ok()) {
        throw BftClockIpcError(status.error_message());
    }

    if (response.request_id() != request_id) {
        throw BftClockIpcError("Replay attack detected");
    }

    BftTimeResponseData r;
    r.unix_time_ms            = response.unix_time_ms();
    r.confidence_interval_ms  = response.confidence_interval_ms();
    r.active_nodes            = response.active_nodes();
    r.projected_drift_ppm     = response.projected_drift_ppm();

    return r;
}

} // namespace uml001