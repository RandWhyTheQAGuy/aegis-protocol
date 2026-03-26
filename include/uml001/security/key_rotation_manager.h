/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Gary Gray (github.com/<your-github-handle>)
 *
 * The Aegis Protocol defines a distributed trust and identity framework
 * based on cryptographically verifiable Semantic Passports, capability
 * enforcement, and transparency logging for auditable system behavior.
 *
 * Core components include:
 *   - Semantic Passports: verifiable identity and capability attestations
 *   - Transparency Log: append-only cryptographic audit trail of system events
 *   - Revocation System: deterministic invalidation of compromised or expired identities
 *   - Passport Registry: issuance and verification authority for trusted entities
 *
 * This framework is designed for open standardization, interoperability,
 * and production-grade use in distributed identity, AI systems, and
 * verifiable authorization infrastructures.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for research, verifiable systems design,
 * and deployment in security-critical distributed environments.
 */
#pragma once

/**
 * @file key_rotation_manager.h
 * @brief Periodic HMAC/Ed25519/TPM key rotation for NTP authorities.
 *
 * Manages key lifecycle for the NTP observation HMAC signing scheme:
 *   - Generates new keys at a configurable interval
 *   - Maintains an overlap window (previous key remains valid)
 *   - Registers keys with crypto_verify() global registry
 *   - Logs rotation events to ColdVault
 *   - Supports HMAC, Ed25519, and TPM-sealed Ed25519 modes
 *
 * DoD / NIST references
 * ---------------------
 *   NIST SP 800-57  Key management lifecycle
 *   NIST SP 800-90A CSPRNG key generation
 */

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>

#include "uml001/crypto_mode.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/vault.h"
#include "uml001/ntp_observation_fetcher.h"

namespace uml001 {

class KeyRotationManager {
public:
    struct Config {
        uint64_t rotation_interval_seconds = 3600;  ///< Rotate every N seconds
        uint64_t overlap_window_seconds    = 180;   ///< Old key accepted for N more seconds
        CryptoConfig crypto;                        ///< HMAC / Ed25519 / TPM mode
    };

    /**
     * @param vault        ColdVault for rotation event audit logging.
     * @param authorities  Set of NTP authority hostnames to register keys for.
     * @param config       Rotation configuration.
     */
    KeyRotationManager(ColdVault&                              vault,
                       const std::unordered_set<std::string>& authorities,
                       Config                                  config);

    /**
     * @brief Rotate keys if rotation_interval_seconds has elapsed.
     *
     * Thread-safe. Idempotent if the interval has not elapsed.
     *
     * @param strong_time  BFT-verified unix timestamp (from the trusted clock).
     */
    void maybe_rotate(uint64_t strong_time);

    /**
     * @brief Configure an NtpObservationFetcher with the current active key.
     *
     * No-op in non-HMAC modes.
     */
    void configure_fetcher(NtpObservationFetcher& fetcher);

    /**
     * @brief Verify a signature against the current key or the previous key
     *        if within the overlap window.
     *
     * Supports zero-downtime key rotation: observations signed with the
     * previous key are accepted until previous_key_expiry_ has passed.
     *
     * @param authority   Authority hostname.
     * @param payload     Signed payload string.
     * @param signature   Hex-encoded signature.
     * @param strong_time Current BFT-verified time (for overlap check).
     * @return true if the signature is valid under the current or previous key.
     */
    bool verify_with_overlap(const std::string& authority,
                             const std::string& payload,
                             const std::string& signature,
                             uint64_t           strong_time);

    uint64_t   key_version() const;
    CryptoMode mode()        const;

private:
    void rotate_hmac(uint64_t strong_time);
    void rotate_ed25519(uint64_t strong_time);
    void rotate_tpm(uint64_t strong_time);

    bool verify_hmac(const std::string& authority,
                     const std::string& payload,
                     const std::string& signature,
                     const std::string& key_hex);

    bool verify_ed25519(const std::string& payload,
                        const std::string& signature,
                        const std::string& pubkey_hex);

    ColdVault&                              vault_;
    std::unordered_set<std::string>         authorities_;
    Config                                  config_;

    // HMAC keys (hex-encoded, 32 raw bytes)
    std::string current_hmac_;
    std::string previous_hmac_;
    std::string current_key_id_;
    std::string previous_key_id_;

    // Ed25519 keys (hex-encoded)
    std::string current_private_key_;
    std::string current_public_key_;
    std::string previous_public_key_;

    uint64_t previous_key_expiry_ = 0;
    uint64_t key_version_         = 0;
    uint64_t last_rotation_unix_  = 0;

    mutable std::mutex mutex_;
};

} // namespace uml001