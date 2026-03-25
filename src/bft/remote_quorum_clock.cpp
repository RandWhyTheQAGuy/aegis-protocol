#include "uml001/crypto/crypto_utils.h"
#include "uml001/bft/remote_quorum_clock.h"
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
<<<<<<< HEAD
    
    for (const auto& n : nodes) {
        auto channel = grpc::CreateChannel(n.endpoint, grpc::InsecureChannelCredentials());
=======
<<<<<<< HEAD
    if (quorum_threshold == 0 || quorum_threshold > nodes.size())
        throw std::invalid_argument("Invalid quorum threshold");

    // Initialize gRPC channels for each time server node
    for (const auto& n : nodes) {
        auto channel = grpc::CreateChannel(n.endpoint, grpc::InsecureChannelCredentials());

=======
    
    for (const auto& n : nodes) {
        auto channel = grpc::CreateChannel(n.endpoint, grpc::InsecureChannelCredentials());
>>>>>>> cc5bbf5 (WIP: continued clean integration and BFT hardening updates)
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
        NodeClient c;
        c.endpoint = n.endpoint;
        c.node_id = n.node_id;
        c.pubkey = uml001::base64_decode(n.pubkey_base64);
        c.stub = quorumtime::ClockService::NewStub(channel);
        clients_.push_back(std::move(c));
    }
}

<<<<<<< HEAD
uint64_t RemoteQuorumClock::now_unix() const {
    // 1. Generate a unique ID for this request to prevent "Replay Attacks"
    std::string request_id = uml001::generate_random_bytes_hex(16);

=======
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
>>>>>>> cc5bbf5 (WIP: continued clean integration and BFT hardening updates)
    std::vector<int64_t> times;
    std::vector<double> confs;
    std::vector<double> drifts;

<<<<<<< HEAD
=======
<<<<<<< HEAD
    // Reset the cryptographic proof for this round
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
    last_proof_ = {};

    // 2. Poll every node in the cluster
    for (const auto& c : clients_) {
        quorumtime::TimeResponse r;
<<<<<<< HEAD
=======

=======
    last_proof_ = {};

    // 2. Poll every node in the cluster
    for (const auto& c : clients_) {
        quorumtime::TimeResponse r;
>>>>>>> cc5bbf5 (WIP: continued clean integration and BFT hardening updates)
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
        if (!query_node(c, request_id, r)) continue;
        if (!validate_response(c, r, request_id)) continue;

        times.push_back(r.unix_time_ms());
        confs.push_back(r.confidence_interval_ms());
        drifts.push_back(r.projected_drift_ppm());

<<<<<<< HEAD
=======
<<<<<<< HEAD
        // Store evidence for the QuorumProof
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
        last_proof_.node_ids.push_back(c.node_id);
        last_proof_.signatures_b64.push_back(
            uml001::base64_encode(std::vector<uint8_t>(r.signature().begin(), r.signature().end()))
        );
    }

    // 3. Ensure we have enough valid responses to reach agreement
    if (times.size() < quorum_threshold_) {
        active_nodes_ = static_cast<int>(times.size());
        throw std::runtime_error("Quorum not reached");
    }

    // 4. Calculate the median time (resistant to "liar" nodes)
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

bool RemoteQuorumClock::query_node(const NodeClient& client, const std::string& request_id, quorumtime::TimeResponse& out) const {
    quorumtime::TimeRequest req;
    req.set_client_id("aegis_core");
    req.set_request_id(req_id);
    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(1000));
    return client.stub->GetQuorumTime(&ctx, req, &out).ok();
}

bool RemoteQuorumClock::validate_response(const NodeClient& client, const quorumtime::TimeResponse& r, const std::string& request_id) const {
    // Verify request pairing
    if (r.request_id() != request_id) return false;
    if (r.node_id() != client.node_id) return false;

    // Cryptographic signature check (Ed25519)
    auto payload = canonical_payload(r);
    auto sig = std::vector<uint8_t>(r.signature().begin(), r.signature().end());

    if (!uml001::ed25519_verify(client.pubkey, std::vector<uint8_t>(payload.begin(), payload.end()), sig)) {
        return false;
    }

    // Use injected clock for time instead of std::chrono
    int64_t now_ms = clock_.now_ms();
    return std::abs(now_ms - r.unix_time_ms()) <= max_skew_ms_;
}

std::string RemoteQuorumClock::canonical_payload(const quorumtime::TimeResponse& r) const {
    // Create a predictable string for hashing/signing
    std::ostringstream ss;
    ss << r.unix_time_ms() << "|" << r.confidence_interval_ms() << "|" 
       << r.active_nodes() << "|" << r.projected_drift_ppm() << "|" 
       << r.request_id() << "|" << r.node_id();
    return ss.str();
}

int64_t RemoteQuorumClock::compute_median(std::vector<int64_t>& v) const {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

void RemoteQuorumClock::enforce_monotonic(int64_t t) const {
    int64_t prev = monotonic_floor_.load();
    // Atomic Compare-and-Swap to update floor safely across threads
    while (t > prev && !monotonic_floor_.compare_exchange_weak(prev, t, std::memory_order_release, std::memory_order_relaxed)) {}
    
    if (t < prev) {
        throw std::runtime_error("Security Alert: Trusted Time rollback detected");
    }
}

<<<<<<< HEAD
// Metric Accessors
=======
// Metric Getters
=======
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

    // Return as uint64_t to satisfy IClock interface
    return static_cast<uint64_t>(median);
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

    // Use injected clock for time instead of std::chrono
    int64_t now_ms = clock_.now_ms();
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
>>>>>>> cc5bbf5 (WIP: continued clean integration and BFT hardening updates)
>>>>>>> fe79fa5 (Remove e2e-example references and resolve all merge conflicts for production-ready main branch)
double RemoteQuorumClock::get_confidence_ms() const { return confidence_; }
int RemoteQuorumClock::get_active_nodes() const { return active_nodes_; }
double RemoteQuorumClock::get_projected_drift() const { return drift_; }
const QuorumProof& RemoteQuorumClock::last_proof() const { return last_proof_; }

// IClock Interface Methods
uint64_t RemoteQuorumClock::now_ms() const {
    // Convert seconds to milliseconds
    uint64_t sec_time = now_unix();
    return sec_time * 1000;
}

bool RemoteQuorumClock::is_synchronized() const {
    return current_status_ == ClockStatus::SYNCHRONIZED;
}

uint64_t RemoteQuorumClock::last_sync_unix() const {
    return last_sync_time_;
}

ClockStatus RemoteQuorumClock::status() const {
    // Update status based on active nodes and confidence
    if (active_nodes_ == 0) {
        return ClockStatus::FAULT;
    } else if (active_nodes_ < static_cast<int>(quorum_threshold_)) {
        return ClockStatus::DEGRADED;
    } else if (drift_ > max_drift_ppm_ * 0.8) {
        return ClockStatus::DEGRADED;
    } else {
        return ClockStatus::SYNCHRONIZED;
    }
}

std::string RemoteQuorumClock::source_id() const {
    return "BFT-Quorum";
}

} // namespace uml001