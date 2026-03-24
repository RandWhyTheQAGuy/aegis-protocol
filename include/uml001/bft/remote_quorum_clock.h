/*
 * Copyright 2026 Aegis Protocol Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#pragma once

#include "uml001/core/clock.h"
#include <string>
#include <memory>

namespace uml001 {

/**
 * @brief Implementation of IClock that fetches time from the BFT Quorum.
 */
class RemoteQuorumClock : public IClock {
public:
    RemoteQuorumClock(const std::string& quorum_address);
    virtual ~RemoteQuorumClock() = default;

    // Interface Implementation (Fixes the 'abstract class' and 'hidden virtual' errors)
    uint64_t now_unix() const override;
    uint64_t now_ms() const override;
    bool is_synchronized() const override;
    uint64_t last_sync_unix() const override;
    ClockStatus status() const override;
    std::string source_id() const override;

    // BFT Specific control
    void trigger_sync();

private:
    std::string quorum_address_;
    mutable ClockStatus current_status_{ClockStatus::UNKNOWN};
};

} // namespace uml001