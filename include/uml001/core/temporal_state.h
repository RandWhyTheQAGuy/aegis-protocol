#pragma once

namespace uml001 {

enum class TemporalState {
    SYNCHRONIZED,
    CACHED,
    DEGRADED,
    UNTRUSTED
};

}