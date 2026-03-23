#include "uml001/core/remote_quorum_clock.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace uml001 {

RemoteQuorumClock::RemoteQuorumClock(
    const std::vector<NodeConfig>& nodes,
    size_t quorum_threshold,
    int64_t max_skew_ms,
    double max_drift_ppm
)
    : quorum_threshold_(quorum_threshold),
      max_skew_ms_(max_skew_ms),
      max_drift_ppm_(max_drift_ppm)
{
    if (nodes.empty()) throw std::invalid_argument("No nodes provided");
    if (quorum_threshold == 0 || quorum_threshold > nodes.size())
        throw std::invalid_argument("Invalid quorum threshold");

    for (const auto& n : nodes) {
        auto channel = grpc::CreateChannel(
            n.endpoint,
            grpc::InsecureChannelCredentials());

        NodeClient c;
        c.endpoint = n.endpoint;
        c.node_id = n.node_id;
        c.pubkey = base64_decode(n.pubkey_base64);
        c.stub = quorumtime::ClockService::NewStub(channel);

        clients_.push_back(std::move(c));
    }
}

bool RemoteQuorumClock::query_node(
    NodeClient& client,
    const std::string& request_id,
    quorumtime::TimeResponse& out
) {
    quorumtime::TimeRequest req;
    req.set_client_id("aegis");
    req.set_request_id(request_id);

    grpc::ClientContext ctx;

    return client.stub->GetQuorumTime(&ctx, req, &out).ok();
}

std::string RemoteQuorumClock::canonical_payload(const quorumtime::TimeResponse& r) {
    std::ostringstream ss;
    ss << r.unix_time_ms() << "|"
       << r.confidence_interval_ms() << "|"
       << r.active_nodes() << "|"
       << r.projected_drift_ppm() << "|"
       << r.request_id() << "|"
       << r.node_id();
    return ss.str();
}

bool RemoteQuorumClock::validate_response(
    const NodeClient& client,
    const quorumtime::TimeResponse& r,
    const std::string& request_id
) {
    if (r.request_id() != request_id) return false;
    if (r.node_id() != client.node_id) return false;

    auto payload = canonical_payload(r);
    auto sig = std::vector<uint8_t>(r.signature().begin(), r.signature().end());

    if (!ed25519_verify(client.pubkey,
                        std::vector<uint8_t>(payload.begin(), payload.end()),
                        sig))
        return false;

    auto now = std::chrono::system_clock::now().time_since_epoch();
    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

    if (std::abs(now_ms - r.unix_time_ms()) > max_skew_ms_)
        return false;

    if (r.projected_drift_ppm() > max_drift_ppm_)
        return false;

    return true;
}

int64_t RemoteQuorumClock::compute_median(std::vector<int64_t>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

void RemoteQuorumClock::enforce_monotonic(int64_t t) {
    int64_t prev = monotonic_floor_.load();
    while (t > prev && !monotonic_floor_.compare_exchange_weak(prev, t)) {}
    if (t < prev) throw std::runtime_error("Time rollback detected");
}

int64_t RemoteQuorumClock::now_unix() {
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
        last_proof_.signatures_b64.push_back(
            base64_encode(std::vector<uint8_t>(r.signature().begin(), r.signature().end()))
        );
    }

    if (times.size() < quorum_threshold_) {
        throw std::runtime_error("Quorum not reached");
    }

    int64_t median = compute_median(times);

    enforce_monotonic(median);

    last_time_ = median;
    last_proof_.median_time_ms = median;

    double sum_conf = 0;
    for (auto c : confs) sum_conf += c;
    confidence_ = sum_conf / confs.size();

    double sum_drift = 0;
    for (auto d : drifts) sum_drift += d;
    drift_ = sum_drift / drifts.size();

    active_nodes_ = times.size();

    return median;
}

double RemoteQuorumClock::get_confidence_ms() const { return confidence_; }
int RemoteQuorumClock::get_active_nodes() const { return active_nodes_; }
double RemoteQuorumClock::get_projected_drift() const { return drift_; }
const QuorumProof& RemoteQuorumClock::last_proof() const { return last_proof_; }

} // namespace uml001