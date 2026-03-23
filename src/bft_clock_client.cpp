#include "uml001/bft_clock_client.h"
#include "uml001/crypto_utils.h"

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

} // namespace uml001