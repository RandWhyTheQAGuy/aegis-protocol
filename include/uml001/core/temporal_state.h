#pragma once

#include <cstdint>
#include <string>

namespace uml001 {

/**
 * @brief TemporalState reflects the BFT Quorum health.
 */
enum class TemporalState {
    SYNCHRONIZED, ///< Quorum reached, uncertainty < 50ms
    CACHED,       ///< IPC alive, but relying on local drift (Uncertainty 50-200ms)
    DEGRADED,     ///< Drift/Skew exceeding safety window (Uncertainty > 200ms)
    UNTRUSTED     ///< Quorum lost or Signature mismatch. STOP ALL OPS.
};

class TemporalStateMachine {
public:
    TemporalStateMachine() : current_state_(TemporalState::UNTRUSTED) {}

    /**
     * @brief Updates state based on BFT metrics from the sidecar.
     * @param uncertainty_ms The current confidence interval from the Quorum.
     * @param drift_ppm The parts-per-million drift of the local oscillator.
     */
    void update(double uncertainty_ms, double drift_ppm) {
        if (uncertainty_ms < 50.0 && drift_ppm < 100.0) {
            current_state_ = TemporalState::SYNCHRONIZED;
        } else if (uncertainty_ms < 200.0) {
            current_state_ = TemporalState::CACHED;
        } else if (uncertainty_ms < 1000.0 || drift_ppm > 500.0) {
            current_state_ = TemporalState::DEGRADED;
        } else {
            current_state_ = TemporalState::UNTRUSTED;
        }
    }

    TemporalState state() const { return current_state_; }

    static std::string state_str(TemporalState s) {
        switch (s) {
            case TemporalState::SYNCHRONIZED: return "SYNCHRONIZED";
            case TemporalState::CACHED:       return "CACHED";
            case TemporalState::DEGRADED:     return "DEGRADED";
            case TemporalState::UNTRUSTED:    return "UNTRUSTED";
            default:                          return "UNKNOWN";
        }
    }

private:
    TemporalState current_state_;
};

} // namespace uml001