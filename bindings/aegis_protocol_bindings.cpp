/*
 * Aegis Protocol (Semantic Passport System)
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
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

/*
 * Aegis Protocol (Semantic Passport System)
 * Python Bindings (Production-Ready)
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include "uml001/core/clock.h"
#include "uml001/core/passport.h"
#include "uml001/core/registry.h"
#include "uml001/core/session.h"
#include "uml001/core/policy.h"
#include "uml001/core/handshake.h"

#include "uml001/security/vault.h"
#include "uml001/security/transparency_log.h"
#include "uml001/security/revocation.h"
#include "uml001/security/multi_party_issuance.h"
#include "uml001/security/key_rotation.h"
#include "uml001/security/key_manager.h"

#include "uml001/crypto/crypto_utils.h"
#include "uml001/crypto/crypto_facade.h"

namespace py = pybind11;
using namespace uml001;

PYBIND11_MODULE(aegis_protocol, m) {
    m.doc() = "Python bindings for Aegis Protocol (UML-001)";

    // =========================================================================
    // CRYPTO V2 (Facade)
    // =========================================================================
    py::module_ crypto_m = m.def_submodule("crypto_v2", "Production crypto facade");

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

    // =========================================================================
    // KEY MANAGEMENT
    // =========================================================================
    py::class_<security::KeyManager>(m, "KeyManager")
        .def(py::init<>())
        .def("create_aes_key", &security::KeyManager::create_aes_key)
        .def("get_key", &security::KeyManager::get_key)
        .def("revoke_key", &security::KeyManager::revoke_key);

    // =========================================================================
    // CLOCK
    // =========================================================================
    py::class_<IClock, std::shared_ptr<IClock>>(m, "IClock");

    m.def("init_clock", &init_clock);
    m.def("get_clock", &get_clock);
    m.def("now_unix", &now_unix);
    m.def("validate_timestamp", &validate_timestamp);

    // =========================================================================
    // VAULT
    // =========================================================================
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
                const std::string &et,
                const std::string &sid,
                const std::string &aid,
                const std::string &ph,
                const std::string &md,
                uint64_t ts) {
                 v.append(et, sid, aid, ph, md, ts);
             })
        .def("entry_count", &ColdVault::entry_count);

    // =========================================================================
    // TRANSPARENCY LOG (MUST COME BEFORE REGISTRY)
    // =========================================================================
    py::enum_<TransparencyMode>(m, "TransparencyMode")
        .value("IMMEDIATE", TransparencyMode::IMMEDIATE)
        .value("BATCHED", TransparencyMode::BATCHED)
        .export_values();

    py::class_<TransparencyLog>(m, "TransparencyLog")
        .def(py::init<IClock*, TransparencyMode>(),
             py::arg("clock"),
             py::arg("mode"))
        .def("append", &TransparencyLog::append)
        .def("verify_chain", &TransparencyLog::verify_chain)
        .def("entries_for_model", &TransparencyLog::entries_for_model);

    // =========================================================================
    // REVOCATION (DEPENDS ON TLOG)
    // =========================================================================
    py::class_<RevocationList>(m, "RevocationList")
        .def(py::init<TransparencyLog &>())
        .def("revoke", &RevocationList::revoke)
        .def("is_revoked", &RevocationList::is_revoked);

    // =========================================================================
    // PASSPORT + CAPABILITIES
    // =========================================================================
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

    // =========================================================================
    // PASSPORT REGISTRY (CORE)
    // =========================================================================
    py::class_<PassportRegistry>(m, "PassportRegistry")
        .def(py::init<TransparencyLog &,
                      RevocationList &,
                      IClock &,
                      ColdVault &>(),
             py::arg("tlog"),
             py::arg("revocation_list"),
             py::arg("clock"),
             py::arg("vault"))
        .def("issue_model_passport",
             &PassportRegistry::issue_model_passport,
             py::arg("model_id"),
             py::arg("version"),
             py::arg("caps"),
             py::arg("policy_hash"),
             py::arg("ttl_s"))
        .def("verify", &PassportRegistry::verify)
        .def("issue_recovery_token", &PassportRegistry::issue_recovery_token);

    // =========================================================================
    // POLICY ENGINE
    // =========================================================================
    py::enum_<PolicyAction>(m, "PolicyAction")
        .value("ALLOW", PolicyAction::ALLOW)
        .value("FLAG", PolicyAction::FLAG)
        .value("DENY", PolicyAction::DENY)
        .value("DENY_CONF", PolicyAction::DENY_CONF)
        .export_values();

    py::class_<PolicyEngine>(m, "PolicyEngine")
        .def(py::init<const CompatibilityManifest &,
                      const std::vector<PolicyRule> &,
                      PolicyAction>())
        .def("evaluate", &PolicyEngine::evaluate);

    // =========================================================================
    // SESSION
    // =========================================================================
    py::class_<Session>(m, "Session")
        .def(py::init<const std::string &,
                      const std::string &,
                      const FlushCallback &,
                      const SessionConfig &>())
        .def("activate", &Session::activate)
        .def("state", &Session::state)
        .def("process_decision", &Session::process_decision)
        .def("entropy_flush", &Session::entropy_flush)
        .def("complete_flush", &Session::complete_flush)
        .def("reactivate", &Session::reactivate)
        .def("close", &Session::close);

    // =========================================================================
    // HANDSHAKE
    // =========================================================================
    py::class_<HandshakeValidator>(m, "HandshakeValidator")
        .def(py::init<PassportRegistry &,
                      const SemanticPassport &,
                      const std::string &,
                      const std::string &,
                      NonceCache &,
                      uint64_t,
                      bool,
                      bool>())
        .def("build_hello", &HandshakeValidator::build_hello)
        .def("handle_hello", &HandshakeValidator::handle_hello)
        .def("handle_challenge", &HandshakeValidator::handle_challenge)
        .def("handle_confirm", &HandshakeValidator::handle_confirm);

    // =========================================================================
    // MULTI-PARTY ISSUANCE
    // =========================================================================
    py::class_<MultiPartyIssuer>(m, "MultiPartyIssuer")
        .def(py::init<PassportRegistry &, uint32_t>())
        .def("propose", &MultiPartyIssuer::propose)
        .def("countersign", &MultiPartyIssuer::countersign)
        .def("reject", &MultiPartyIssuer::reject)
        .def("get_finalized_passport", &MultiPartyIssuer::get_finalized_passport)
        .def("expire_stale_proposals", &MultiPartyIssuer::expire_stale_proposals);
}