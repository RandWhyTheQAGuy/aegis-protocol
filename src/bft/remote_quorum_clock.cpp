#include "uml001/remote_quorum_clock.h"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <cmath>

namespace uml001 {

RemoteQuorumClock::RemoteQuorumClock(
    const std::vector<NodeConfig>& nodes,
    size_t quorum_threshold,
    int64_t max_skew_ms,
    double max_drift_ppm
) : quorum_threshold_(quorum_threshold),
    max_skew_ms_(max_skew_ms),
    max_drift_ppm_(max_drift_ppm) {
    
    if (nodes.empty()) throw std::invalid_argument("No nodes provided");
    
    for (const auto& n : nodes) {
        auto channel = grpc::CreateChannel(n.endpoint, grpc::InsecureChannelCredentials());
        NodeClient c;
        c.endpoint = n.endpoint;
        c.node_id = n.node_id;
        c.pubkey = base64_decode(n.pubkey_base64);
        c.stub = quorumtime::ClockService::NewStub(channel);
        clients_.push_back(std::move(c));
    }
}

// IClock Interface Implementation
uint64_t RemoteQuorumClock::now_ms() const {
    // Logical const-ness: sync modifies internal cache/metrics
    return static_cast<uint64_t>(const_cast<RemoteQuorumClock*>(this)->perform_sync());
}

uint64_t RemoteQuorumClock::now_unix() const {
    return now_ms() / 1000;
}

bool RemoteQuorumClock::is_synchronized() const {
    return status() == ClockStatus::SYNCHRONIZED;
}

uint64_t RemoteQuorumClock::last_sync_unix() const {
    return static_cast<uint64_t>(last_time_ / 1000);
}

ClockStatus RemoteQuorumClock::status() const {
    if (active_nodes_ == 0) return ClockStatus::UNKNOWN;
    if (active_nodes_ < (int)quorum_threshold_) return ClockStatus::FAULT;
    if (drift_ > max_drift_ppm_) return ClockStatus::DEGRADED;
    return ClockStatus::SYNCHRONIZED;
}

std::string RemoteQuorumClock::source_id() const {
    return "BFT-Quorum-Clock";
}

// BFT Internal Logic
int64_t RemoteQuorumClock::perform_sync() {
    std::string request_id = generate_random_bytes_hex(16);
    std::vector<int64_t> times;
    std::vector<double> confs;
    std::vector<double> drifts;

    last_proof_ = {};

    for (auto& c : clients_) {
        quorumtime::TimeResponse r;
        if (!query_node(c, request_id, r)) continue;
        if (!validate_response(c, r, request_id)) continue;

        times.push_back(r.unix_time_ms());
        confs.push_back(r.confidence_interval_ms());
        drifts.push_back(r.projected_drift_ppm());

        last_proof_.node_ids.push_back(c.node_id);
        last_proof_.signatures_b64.push_back(base64_encode(
            std::vector<uint8_t>(r.signature().begin(), r.signature().end())));
    }

    if (times.size() < quorum_threshold_) {
        active_nodes_ = static_cast<int>(times.size());
        throw std::runtime_error("Quorum not reached");
    }

    int64_t median = compute_median(times);
    enforce_monotonic(median);

    // Update state
    last_time_ = median;
    last_proof_.median_time_ms = median;
    active_nodes_ = static_cast<int>(times.size());
    
    double sum_conf = 0, sum_drift = 0;
    for (size_t i = 0; i < times.size(); ++i) {
        sum_conf += confs[i];
        sum_drift += drifts[i];
    }
    confidence_ = sum_conf / times.size();
    drift_ = sum_drift / times.size();

    return median;
}

bool RemoteQuorumClock::query_node(NodeClient& client, const std::string& req_id, quorumtime::TimeResponse& out) {
    quorumtime::TimeRequest req;
    req.set_client_id("aegis_core");
    req.set_request_id(req_id);
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(1000));
    return client.stub->GetQuorumTime(&ctx, req, &out).ok();
}

bool RemoteQuorumClock::validate_response(const NodeClient& client, const quorumtime::TimeResponse& r, const std::string& req_id) {
    if (r.request_id() != req_id || r.node_id() != client.node_id) return false;
    
    auto payload = canonical_payload(r);
    std::vector<uint8_t> sig(r.signature().begin(), r.signature().end());
    if (!ed25519_verify(client.pubkey, std::vector<uint8_t>(payload.begin(), payload.end()), sig)) return false;

    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return std::abs(now_ms - r.unix_time_ms()) <= max_skew_ms_;
}

std::string RemoteQuorumClock::canonical_payload(const quorumtime::TimeResponse& r) {
    std::ostringstream ss;
    ss << r.unix_time_ms() << "|" << r.confidence_interval_ms() << "|" 
       << r.active_nodes() << "|" << r.projected_drift_ppm() << "|" 
       << r.request_id() << "|" << r.node_id();
    return ss.str();
}

int64_t RemoteQuorumClock::compute_median(std::vector<int64_t>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

void RemoteQuorumClock::enforce_monotonic(int64_t t) {
    int64_t prev = monotonic_floor_.load();
    while (t > prev && !monotonic_floor_.compare_exchange_weak(prev, t)) {}
    if (t < prev) throw std::runtime_error("Time rollback detected in Quorum");
}

// Metric Accessors
double RemoteQuorumClock::get_confidence_ms() const { return confidence_; }
int RemoteQuorumClock::get_active_nodes() const { return active_nodes_; }
double RemoteQuorumClock::get_projected_drift() const { return drift_; }
const QuorumProof& RemoteQuorumClock::last_proof() const { return last_proof_; }

} // namespace uml001