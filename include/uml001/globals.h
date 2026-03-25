#pragma once

#include "uml001/core/clock.h"
#include <memory>

namespace uml001 {

// Global clock instance management (singleton pattern)
// These functions are used by main_aegis_protocol.cpp and Python bindings

/**
 * @brief Register a global clock instance for use throughout the system
 */
void init_clock(std::shared_ptr<IClock> clock);

/**
 * @brief Retrieve the registered global clock instance
 */
std::shared_ptr<IClock> get_clock();

/**
 * @brief Get current Unix time via the global clock
 */
uint64_t now_unix();

/**
 * @brief Validate a timestamp against the global clock's safety bounds
 */
bool validate_timestamp(uint64_t timestamp_unix);

} // namespace uml001
