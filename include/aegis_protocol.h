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

#include "clock.h"
#include "vault.h"
#include "crypto_utils.h"
#include "session.h"
#include "policy.h"
#include "passport.h"
#include "handshake.h"
#include "multi_party_issuance.h"
#include "uml001/security/transparency_log.h"
#include "key_rotation.h"
#include "revocation.h"

namespace py = pybind11;
using namespace uml001;

PYBIND11_MODULE(aegis_protocol, m) {
    m.doc() = "Python bindings for UML-001 Aegis protocol";

    // -------------------------------------------------------------------------
    // Clock / global NOW
    // -------------------------------------------------------------------------
    py::class_<IClock, std::shared_ptr<IClock>>(m, "IClock");

    m.def("init_clock", &init_clock, "Register global clock");
    m.def("get_clock", &get_clock, "Get global clock");
    m.def("now_unix", &now_unix, "Return current Unix time via global clock");
    m.def("validate_timestamp", &validate_timestamp, "Validate timestamp against global clock");

    // -------------------------------------------------------------------------
    // Vault
    // -------------------------------------------------------------------------
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
             [](ColdVault &v,
                const std::string &event_type,
                const std::string &session_id,
                const std::string &actor_id,
                const std::string &payload_hash,
                const std::string &metadata,
                uint64_t ts) {
                 v.append(event_type, session_id, actor_id, payload_hash, metadata, ts);
             })
        .def("entry_count", &ColdVault::entry_count);

    // -------------------------------------------------------------------------
    // Crypto helpers
    // -------------------------------------------------------------------------
    m.def("sha256_hex", &sha256_hex);
    m.def("hmac_sha256_hex", &hmac_sha256_hex);
    m.def("generate_random_bytes_hex", &generate_random_bytes_hex);

    // -------------------------------------------------------------------------
    // Passport / identity
    // -------------------------------------------------------------------------
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
        .def(py::init<const std::string &, const std::string &, std::shared_ptr<IClock>>(),
             py::arg("root_key"), py::arg("registry_version"), py::arg("clock"))
        .def("issue",
             [](PassportRegistry &r,
                const std::string &model_id,
                const std::string &version,
                const Capabilities &caps,
                const std::string &policy_hash,
                uint64_t ttl_s) {
                 return r.issue(model_id, version, caps, policy_hash, ttl_s);
             },
             py::arg("model_id"), py::arg("version"),
             py::arg("caps"), py::arg("policy_hash"), py::arg("ttl_s"))
        .def("verify", &PassportRegistry::verify)
        .def("issue_recovery_token",
             &PassportRegistry::issue_recovery_token,
             py::arg("passport"), py::arg("incident_id"));

    // -------------------------------------------------------------------------
    // Policy engine
    // -------------------------------------------------------------------------
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
        .def(py::init<const CompatibilityManifest &,
                      const std::vector<PolicyRule> &,
                      PolicyAction>(),
             py::arg("manifest"), py::arg("rules"), py::arg("default_action"))
        .def("evaluate", &PolicyEngine::evaluate);

    // -------------------------------------------------------------------------
    // Session
    // -------------------------------------------------------------------------
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
        .def(py::init<const std::string &,
                      const std::string &,
                      const FlushCallback &,
                      const SessionConfig &>(),
             py::arg("session_id"),
             py::arg("model_id"),
             py::arg("flush_cb"),
             py::arg("config"))
        .def("activate", &Session::activate)
        .def("state", &Session::state)
        .def("process_decision", &Session::process_decision)
        .def("entropy_flush", &Session::entropy_flush)
        .def("complete_flush", &Session::complete_flush)
        .def("reactivate", &Session::reactivate)
        .def("close", &Session::close);

    // -------------------------------------------------------------------------
    // Handshake
    // -------------------------------------------------------------------------
    py::class_<NonceCache>(m, "NonceCache")
        .def(py::init<uint64_t, size_t>(),
             py::arg("ttl_seconds"), py::arg("max_entries"));

    py::class_<SessionContext>(m, "SessionContext")
        .def_readonly("session_id", &SessionContext::session_id)
        .def_readonly("session_key_hex", &SessionContext::session_key_hex)
        .def_readonly("forward_secrecy", &SessionContext::forward_secrecy)
        .def_readonly("transport_id", &SessionContext::transport_id)
        .def_readonly("established_at", &SessionContext::established_at)
        .def("derive_direction_key", &SessionContext::derive_direction_key)
        .def("authenticate_payload", &SessionContext::authenticate_payload);

    py::class_<HandshakeValidator>(m, "HandshakeValidator")
        .def(py::init<PassportRegistry &,
                      const SemanticPassport &,
                      const std::string &,
                      const std::string &,
                      NonceCache &,
                      uint64_t,
                      bool,
                      bool>(),
             py::arg("registry"),
             py::arg("passport"),
             py::arg("schema"),
             py::arg("transport_id"),
             py::arg("nonce_cache"),
             py::arg("expiry_ts"),
             py::arg("reject_recovered"),
             py::arg("require_strong"))
        .def("build_hello", &HandshakeValidator::build_hello)
        .def("handle_hello", &HandshakeValidator::handle_hello)
        .def("handle_challenge", &HandshakeValidator::handle_challenge)
        .def("handle_confirm", &HandshakeValidator::handle_confirm);

    // -------------------------------------------------------------------------
    // Multi-party issuance
    // -------------------------------------------------------------------------
    py::class_<MultiPartyIssuer>(m, "MultiPartyIssuer")
        .def(py::init<PassportRegistry &, uint32_t>(),
             py::arg("registry"), py::arg("quorum"))
        .def("propose", &MultiPartyIssuer::propose)
        .def("countersign", &MultiPartyIssuer::countersign)
        .def("reject", &MultiPartyIssuer::reject)
        .def("get_finalized_passport", &MultiPartyIssuer::get_finalized_passport)
        .def("expire_stale_proposals", &MultiPartyIssuer::expire_stale_proposals);

    // -------------------------------------------------------------------------
    // Revocation / key rotation
    // -------------------------------------------------------------------------
    py::class_<RevocationList>(m, "RevocationList")
        .def(py::init<>())
        .def("revoke", &RevocationList::revoke)
        .def("is_revoked", &RevocationList::is_revoked);

    py::class_<KeyStore>(m, "KeyStore")
        .def(py::init<const std::string &>(),
             py::arg("root_key"))
        .def("active_key_id", &KeyStore::active_key_id)
        .def("begin_rotation", &KeyStore::begin_rotation)
        .def("complete_rotation", &KeyStore::complete_rotation)
        .def("purge_expired_keys", &KeyStore::purge_expired_keys)
        .def("key_metadata", &KeyStore::key_metadata);

    // -------------------------------------------------------------------------
    // Transparency log
    // -------------------------------------------------------------------------
    py::class_<TransparencyLog>(m, "TransparencyLog")
        .def(py::init<>())
        .def("append", &TransparencyLog::append)
        .def("verify_chain", &TransparencyLog::verify_chain)
        .def("entries_for_model", &TransparencyLog::entries_for_model);
}
