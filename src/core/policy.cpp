#include "uml001/core/temporal_state.h"

bool allow_write(TemporalState state) {
    return state == TemporalState::SYNCHRONIZED ||
           state == TemporalState::CACHED;
}

bool allow_read(TemporalState state) {
    return state != TemporalState::UNTRUSTED;
}