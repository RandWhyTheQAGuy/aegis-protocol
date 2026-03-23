#include "uml001/core/temporal_state.h"

namespace uml001 {

// Simple helper logic
TemporalState compute_state(double tslq_seconds) {
    if (tslq_seconds < 0.1) return TemporalState::SYNCHRONIZED;
    if (tslq_seconds < 2.0) return TemporalState::CACHED;
    if (tslq_seconds < 10.0) return TemporalState::DEGRADED;
    return TemporalState::UNTRUSTED;
}

}