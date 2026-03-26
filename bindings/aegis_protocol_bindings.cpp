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

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h> // Required for FlushCallback

// Updated paths based on Reorg
#include "uml001/core/clock.h"
#include "uml001/security/vault.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/crypto/crypto_facade.h"
#include "uml001/core/session.h"
#include "uml001/core/policy.h"
#include "uml001/core/passport.h"
#include "uml001/core/handshake.h"
#include "uml001/security/multi_party_issuance.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/key_rotation.h"
#include "uml001/security/revocation.h"
#include "uml001/security/key_manager.h"

namespace py = pybind11;
using namespace uml001;

PYBIND11_MODULE(aegis_protocol, m) {
    m.doc() = "Python bindings for UML-001 Aegis Protocol v2.0";

    // =========================================================================
    // NEW v2.0 FEATURES (Crypto Facade & Key Management)
    // =========================================================================
    
    // Crypto Facade Submodule
    py::module_ crypto_m = m.def_submodule("crypto_v2", "Production-grade Crypto Facade");
    
    py::class_<crypto::Envelope>(crypto_m, "Envelope")
        .def(py::init<>())
        .def_readwrite("ciphertext", &crypto::Envelope::ciphertext)
        .def_readwrite("nonce", &crypto::Envelope::nonce)
        .def_readwrite("tag", &crypto::Envelope::tag);

    crypto_m.def("encrypt_gcm", &crypto::encrypt_gcm);
    crypto_m.def("decrypt_gcm", &crypto::decrypt_gcm);
    crypto_m.def("encrypt_chacha20", &crypto::encrypt_chacha20);
    crypto_m.def("decrypt_chacha20", &crypto::decrypt_chacha20);
    crypto_m.def("sign_payload", &crypto::sign_payload);
    crypto_m.def("verify_signature", &crypto::verify_signature);
    crypto_m.def("to_base64", &crypto::to_base64);
    crypto_m.def("from_base64", &crypto::from_base64);

    // Key Manager
    py::class_<security::KeyManager>(m, "KeyManager")
        .def(py::init<>())
        .def("create_aes_key", &security::KeyManager::create_aes_key)
        .def("get_key", &security::KeyManager::get_key)
        .def("revoke_key", &security::KeyManager::revoke_key);

    // =========================================================================
    // LEGACY & CORE FEATURES (Preserved & Verified)
    // =========================================================================

    // 1. Clock / global NOW
    py::class_<IClock, std::shared_ptr<IClock>>(m, "IClock");
    m.def("init_clock", &init_clock);
    m.def("get_clock", &get_clock);
    m.def("now_unix", &now_unix);
    m.def("validate_timestamp", &validate_timestamp);

    // 2. Vault
    py::class_<VaultConfig>(m, "VaultConfig")
        .def(py::init<>())
        .def_readwrite("vault_path", &VaultConfig::vault_path)
        .def_readwrite("archive_dir", &VaultConfig::archive_dir)
        .def_readwrite("rotate_after_bytes", &VaultConfig::rotate_after_bytes)
        .def_readwrite("rotate_after_entries", &VaultConfig::rotate_after_entries)
        .def_readwrite("compress_on_archive", &VaultConfig::compress_on_archive);

    py::class_<ColdVault>(m, "ColdVault")
        .def(py::init<const VaultConfig &>())
        .def("append",
             [](ColdVault &v, const std::string &et, const std::string &sid, 
                const std::string &aid, const std::string &ph, const std::string &md, uint64_t ts) {
                 v.append(et, sid, aid, ph, md, ts);
             })
        .def("entry_count", &ColdVault::entry_count);

    // 3. Crypto Helpers (Legacy)
    m.def("sha256_hex", &sha256_hex);
    m.def("hmac_sha256_hex", &hmac_sha256_hex);
    m.def("generate_random_bytes_hex", &generate_random_bytes_hex);

    // 4. Passport / Identity
    py::class_<Capabilities>(m, "Capabilities")
        .def(py::init<>())
        .def_readwrite("classifier_authority", &Capabilities::classifier_authority)
        .def_readwrite("classifier_sensitivity", &Capabilities::classifier_sensitivity)
        .def_readwrite("bft_consensus", &Capabilities::bft_consensus)
        .def_readwrite("entropy_flush", &Capabilities::entropy_flush);

    py::class_<SemanticPassport>(m, "SemanticPassport")
        .def_readonly("model_id", &SemanticPassport::model_id)
        .def_readonly("model_version", &SemanticPassport::model_version)
        .def_readonly("policy_hash", &SemanticPassport::policy_hash)
        .def_readonly("ttl_s", &SemanticPassport::ttl_s)
        .def_readonly("issued_at", &SemanticPassport::issued_at)
        .def_readonly("signing_key_id", &SemanticPassport::signing_key_id);

    py::enum_<VerifyStatus>(m, "VerifyStatus")
        .value("OK", VerifyStatus::OK)
        .value("EXPIRED", VerifyStatus::EXPIRED)
        .value("REVOKED", VerifyStatus::REVOKED)
        .value("INVALID_SIGNATURE", VerifyStatus::INVALID_SIGNATURE)
        .value("INCOMPATIBLE", VerifyStatus::INCOMPATIBLE)
        .export_values();

    py::class_<VerifyResult>(m, "VerifyResult")
        .def_readonly("status", &VerifyResult::status)
        .def_readonly("verified_key_id", &VerifyResult::verified_key_id)
        .def_readonly("recovered", &VerifyResult::recovered)
        .def_readonly("confidence", &VerifyResult::confidence)
        .def("ok", &VerifyResult::ok)
        .def("status_str", &VerifyResult::status_str);

    py::class_<PassportRegistry>(m, "PassportRegistry")
        .def(py::init<const std::string &, const std::string &, std::shared_ptr<IClock>>())
        .def("issue", [](PassportRegistry &r, const std::string &mid, const std::string &v, 
                         const Capabilities &c, const std::string &ph, uint64_t ttl) {
                 return r.issue(mid, v, c, ph, ttl);
             })
        .def("verify", &PassportRegistry::verify)
        .def("issue_recovery_token", &PassportRegistry::issue_recovery_token);

    // 5. Policy Engine
    py::enum_<PolicyAction>(m, "PolicyAction")
        .value("ALLOW", PolicyAction::ALLOW)
        .value("FLAG", PolicyAction::FLAG)
        .value("DENY", PolicyAction::DENY)
        .value("DENY_CONF", PolicyAction::DENY_CONF)
        .export_values();

    py::class_<TrustCriteria>(m, "TrustCriteria")
        .def(py::init<>())
        .def_readwrite("min_authority_confidence", &TrustCriteria::min_authority_confidence)
        .def_readwrite("min_sensitivity_confidence", &TrustCriteria::min_sensitivity_confidence);

    py::class_<ScopeCriteria>(m, "ScopeCriteria")
        .def(py::init<>())
        .def_readwrite("authority_min", &ScopeCriteria::authority_min)
        .def_readwrite("sensitivity_max", &ScopeCriteria::sensitivity_max);

    py::class_<PolicyRule>(m, "PolicyRule")
        .def(py::init<>())
        .def_readwrite("rule_id", &PolicyRule::rule_id)
        .def_readwrite("trust", &PolicyRule::trust)
        .def_readwrite("scope", &PolicyRule::scope)
        .def_readwrite("action", &PolicyRule::action);

    py::class_<CompatibilityManifest>(m, "CompatibilityManifest")
        .def(py::init<>())
        .def_readwrite("expected_registry_version", &CompatibilityManifest::expected_registry_version)
        .def_readwrite("policy_hash", &CompatibilityManifest::policy_hash);

    py::class_<PolicyEngine>(m, "PolicyEngine")
        .def(py::init<const CompatibilityManifest &, const std::vector<PolicyRule> &, PolicyAction>())
        .def("evaluate", &PolicyEngine::evaluate);

    // 6. Session
    py::enum_<SessionState>(m, "SessionState")
        .value("INIT", SessionState::INIT)
        .value("ACTIVE", SessionState::ACTIVE)
        .value("SUSPECT", SessionState::SUSPECT)
        .value("QUARANTINE", SessionState::QUARANTINE)
        .value("FLUSHING", SessionState::FLUSHING)
        .value("RESYNC", SessionState::RESYNC)
        .value("CLOSED", SessionState::CLOSED)
        .export_values();

    py::class_<SessionConfig>(m, "SessionConfig")
        .def(py::init<>())
        .def_readwrite("warp_weight_allow", &SessionConfig::warp_weight_allow)
        .def_readwrite("warp_weight_flag", &SessionConfig::warp_weight_flag)
        .def_readwrite("warp_weight_deny", &SessionConfig::warp_weight_deny)
        .def_readwrite("warp_suspect_thresh", &SessionConfig::warp_suspect_thresh)
        .def_readwrite("warp_quarantine_thresh", &SessionConfig::warp_quarantine_thresh);

    py::class_<Session>(m, "Session")
        .def(py::init<const std::string &, const std::string &, const FlushCallback &, const SessionConfig &>())
        .def("activate", &Session::activate)
        .def("state", &Session::state)
        .def("process_decision", &Session::process_decision)
        .def("entropy_flush", &Session::entropy_flush)
        .def("complete_flush", &Session::complete_flush)
        .def("reactivate", &Session::reactivate)
        .def("close", &Session::close);

    // 7. Handshake
    py::class_<NonceCache>(m, "NonceCache")
        .def(py::init<uint64_t, size_t>());

    py::class_<SessionContext>(m, "SessionContext")
        .def_readonly("session_id", &SessionContext::session_id)
        .def_readonly("session_key_hex", &SessionContext::session_key_hex)
        .def_readonly("forward_secrecy", &SessionContext::forward_secrecy)
        .def_readonly("transport_id", &SessionContext::transport_id)
        .def_readonly("established_at", &SessionContext::established_at)
        .def("derive_direction_key", &SessionContext::derive_direction_key)
        .def("authenticate_payload", &SessionContext::authenticate_payload);

    py::class_<HandshakeValidator>(m, "HandshakeValidator")
        .def(py::init<PassportRegistry &, const SemanticPassport &, const std::string &, 
                      const std::string &, NonceCache &, uint64_t, bool, bool>())
        .def("build_hello", &HandshakeValidator::build_hello)
        .def("handle_hello", &HandshakeValidator::handle_hello)
        .def("handle_challenge", &HandshakeValidator::handle_challenge)
        .def("handle_confirm", &HandshakeValidator::handle_confirm);

    // 8. Multi-party Issuance
    py::class_<MultiPartyIssuer>(m, "MultiPartyIssuer")
        .def(py::init<PassportRegistry &, uint32_t>())
        .def("propose", &MultiPartyIssuer::propose)
        .def("countersign", &MultiPartyIssuer::countersign)
        .def("reject", &MultiPartyIssuer::reject)
        .def("get_finalized_passport", &MultiPartyIssuer::get_finalized_passport)
        .def("expire_stale_proposals", &MultiPartyIssuer::expire_stale_proposals);

    // 9. Revocation & Key Rotation
    py::class_<RevocationList>(m, "RevocationList")
        .def(py::init<>())
        .def("revoke", &RevocationList::revoke)
        .def("is_revoked", &RevocationList::is_revoked);

    py::class_<KeyStore>(m, "KeyStore")
        .def(py::init<const std::string &>())
        .def("active_key_id", &KeyStore::active_key_id)
        .def("begin_rotation", &KeyStore::begin_rotation)
        .def("complete_rotation", &KeyStore::complete_rotation)
        .def("purge_expired_keys", &KeyStore::purge_expired_keys)
        .def("key_metadata", &KeyStore::key_metadata);

    // 10. Transparency Log
    py::class_<TransparencyLog>(m, "TransparencyLog")
        .def(py::init<>())
        .def("append", &TransparencyLog::append)
        .def("verify_chain", &TransparencyLog::verify_chain)
        .def("entries_for_model", &TransparencyLog::entries_for_model);
}