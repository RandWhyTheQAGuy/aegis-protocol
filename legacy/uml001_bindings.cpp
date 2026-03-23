// src/python/uml001_bindings.cpp
//
// Polished, full Python bindings for the UML-001 Trusted Time System.
// Exposes core C++ types so pytest can exercise real logic end-to-end.
//
// Change log:
//   [FIX-1]  Added #include "uml001/simple_hash_provider.h"
//   [FIX-2]  Added #include "uml001/file_vault_backend.h"
//   [FIX-3]  Added #include "uml001/simple_file_vault_backend.h"
//   [FIX-4]  ColdVaultConfig gains positional py::init<std::string> overload
//   [FIX-5]  FileVaultBackend binding constructor matches C++ signature
//   [FIX-6]  SimpleFileVaultBackend binding added
//   [FIX-7]  Trampoline PyStrongClock added for Python subclassing of IStrongClock
//   [FIX-8]  Trampoline PyHashProvider added for Python subclassing of IHashProvider
//   [FIX-9]  TimeObservation gains positional py::init overload
//   [FIX-10] BftClockConfig gains keyword py::init overload with defaults
//   [FIX-11] verify_observation exposed on BFTQuorumTrustedClock
//   [FIX-12] read_all() exposed on SimpleFileVaultBackend
//   [FIX-13] FileVaultBackend fsync_on_write defaults to false for test safety
//   [FIX-14] PyStrongClock trampoline methods marked const
//   [FIX-15] Removed duplicate py::init<>() on SimpleFileVaultBackend
//   [FIX-16] TimeObservation positional init argument order corrected
//   [FIX-17] log_sync_event added to ColdVault binding
//   [FIX-18] save_sequence_state docstring corrected
//   [FIX-19] IVaultBackend, SimpleFileVaultBackend, FileVaultBackend switched
//            to py::smart_holder — required for unique_ptr transfer from
//            Python into C++ (pybind11 3.x).
//   [FIX-20] register_hmac_authority exposed as uml001.register_hmac_authority().
//   [FIX-21] BftSyncResult bound as uml001.BftSyncResult. update_and_sync()
//            returns std::optional<BftSyncResult>. pybind11 cannot convert an
//            unregistered C++ type — the binding must exist before the method
//            binding that returns it is compiled, or every call raises:
//              "Unable to convert function return value to a Python type"
//            crypto_verify() looks up HMAC keys from a global registry
//            (g_hmac_keys) keyed by "authority_id|key_id". Tests must call
//            register_hmac_authority() for every authority before any
//            observation is verified — without this every signature check
//            returns false and all sync rounds silently fail with
//            "Insufficient quorum. Valid: 0".

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include <filesystem>
#include <memory>
#include <unordered_set>
#include <vector>
#include <string>

#include "uml001/ntp_observation_fetcher.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/crypto/crypto_utils.h"
#include "uml001/vault.h"
#include "uml001/strong_clock.h"
#include "uml001/vault_logger.h"
#include "uml001/simple_hash_provider.h"       // [FIX-1]
#include "uml001/file_vault_backend.h"          // [FIX-2]
#include "uml001/simple_file_vault_backend.h"   // [FIX-3]

namespace py = pybind11;
using namespace uml001;

// ============================================================
// [FIX-7][FIX-14] Trampoline: IStrongClock
// ============================================================
struct PyStrongClock : public IStrongClock {
    using IStrongClock::IStrongClock;

    uint64_t now_unix() const override {
        PYBIND11_OVERRIDE_PURE(uint64_t, IStrongClock, now_unix);
    }

    int64_t get_current_drift() const override {
        PYBIND11_OVERRIDE_PURE(int64_t, IStrongClock, get_current_drift);
    }
};

// ============================================================
// [FIX-8] Trampoline: IHashProvider
// ============================================================
struct PyHashProvider : public IHashProvider {
    using IHashProvider::IHashProvider;

    std::string sha256(const std::string& input) override {
        PYBIND11_OVERRIDE_PURE(std::string, IHashProvider, sha256, input);
    }
};

PYBIND11_MODULE(uml001, m) {
    m.doc() = "Python bindings for UML-001 Trusted Time System";

    // ------------------------------------------------------------
    // [FIX-20] HMAC key registry
    //
    // crypto_verify() looks up HMAC keys from the global g_hmac_keys map
    // keyed by "authority_id|key_id". The registry is process-global and
    // persists for the lifetime of the module. Tests MUST call
    // register_hmac_authority() for every (authority, key_id) pair before
    // constructing observations — without this every verify returns false
    // and sync rounds fail silently with "Insufficient quorum. Valid: 0".
    //
    // Usage in tests:
    //   SECRET_HEX = "test-hmac-key".encode().hex()
    //   for host in AUTHORITIES:
    //       uml001.register_hmac_authority(host, "v1", SECRET_HEX)
    //
    // The key_hex argument must be a lowercase hex string. The C++ side
    // calls hex_to_bytes() on it before storing.
    // ------------------------------------------------------------
    m.def("register_hmac_authority",
          &register_hmac_authority,
          py::arg("authority_id"),
          py::arg("key_id"),
          py::arg("hmac_key_hex"),
          "Register an HMAC key for a trusted authority in the global key "
          "registry used by crypto_verify(). Must be called for every "
          "(authority_id, key_id) pair before any observation is verified. "
          "hmac_key_hex must be a lowercase hex string (not raw bytes). "
          "Example: uml001.register_hmac_authority('ntp1.test', 'v1', "
          "'74657374...') where the hex encodes the raw HMAC secret.");

    // ------------------------------------------------------------
    // Basic structs and configuration types
    // ------------------------------------------------------------

    // [FIX-9][FIX-16] TimeObservation — field order matches C++ struct:
    //   server_hostname, key_id, unix_seconds, signature_hex, sequence
    py::class_<TimeObservation>(m, "TimeObservation")
        .def(py::init<>())
        .def(py::init([](const std::string& hostname,
                         const std::string& key_id,
                         uint64_t           unix_seconds,
                         const std::string& signature_hex,
                         uint64_t           sequence) {
                TimeObservation obs;
                obs.server_hostname = hostname;
                obs.key_id          = key_id;
                obs.unix_seconds    = unix_seconds;
                obs.signature_hex   = signature_hex;
                obs.sequence        = sequence;
                return obs;
             }),
             py::arg("server_hostname"),
             py::arg("key_id"),
             py::arg("unix_seconds"),
             py::arg("signature_hex"),
             py::arg("sequence"))
        .def_readwrite("server_hostname", &TimeObservation::server_hostname)
        .def_readwrite("key_id",          &TimeObservation::key_id)
        .def_readwrite("unix_seconds",    &TimeObservation::unix_seconds)
        .def_readwrite("signature_hex",   &TimeObservation::signature_hex)
        .def_readwrite("sequence",        &TimeObservation::sequence);

    py::class_<TimestampAttestationToken>(m, "TimestampAttestationToken")
        .def(py::init<>())
        .def_readwrite("unix_time",      &TimestampAttestationToken::unix_time)
        .def_readwrite("median_rtt",     &TimestampAttestationToken::median_rtt)
        .def_readwrite("drift_ppm",      &TimestampAttestationToken::drift_ppm)
        .def_readwrite("quorum_servers", &TimestampAttestationToken::quorum_servers)
        .def_readwrite("quorum_hash",    &TimestampAttestationToken::quorum_hash)
        .def_readwrite("signature",      &TimestampAttestationToken::signature);

    // [FIX-10] BftClockConfig keyword constructor with C++ defaults
    py::class_<BftClockConfig>(m, "BftClockConfig")
        .def(py::init<>())
        .def(py::init([](int64_t  max_drift_step,
                         int64_t  max_total_drift,
                         uint64_t max_cluster_skew,
                         size_t   min_quorum,
                         bool     fail_closed) {
                BftClockConfig cfg;
                cfg.max_drift_step   = max_drift_step;
                cfg.max_total_drift  = max_total_drift;
                cfg.max_cluster_skew = max_cluster_skew;
                cfg.min_quorum       = min_quorum;
                cfg.fail_closed      = fail_closed;
                return cfg;
             }),
             py::arg("max_drift_step")   = int64_t{2},
             py::arg("max_total_drift")  = int64_t{60},
             py::arg("max_cluster_skew") = uint64_t{5},
             py::arg("min_quorum")       = size_t{4},
             py::arg("fail_closed")      = false)
        .def_readwrite("max_drift_step",   &BftClockConfig::max_drift_step)
        .def_readwrite("max_total_drift",  &BftClockConfig::max_total_drift)
        .def_readwrite("max_cluster_skew", &BftClockConfig::max_cluster_skew)
        .def_readwrite("min_quorum",       &BftClockConfig::min_quorum)
        .def_readwrite("fail_closed",      &BftClockConfig::fail_closed);

    // ------------------------------------------------------------
    // Strong clock interface and concrete implementations
    // ------------------------------------------------------------
    py::class_<IStrongClock, PyStrongClock>(m, "IStrongClock")
        .def(py::init<>())
        .def("now_unix",          &IStrongClock::now_unix)
        .def("get_current_drift", &IStrongClock::get_current_drift);

    py::class_<OsStrongClock, IStrongClock>(m, "OsStrongClock")
        .def(py::init<>())
        .def("now_unix",          &OsStrongClock::now_unix)
        .def("get_current_drift", &OsStrongClock::get_current_drift);

    // ------------------------------------------------------------
    // Hash provider interface and concrete implementations
    // ------------------------------------------------------------
    py::class_<IHashProvider, PyHashProvider>(m, "IHashProvider")
        .def(py::init<>())
        .def("sha256", &IHashProvider::sha256, py::arg("input"));

    py::class_<SimpleHashProvider, IHashProvider>(m, "SimpleHashProvider")
        .def(py::init<>())
        .def("sha256", &SimpleHashProvider::sha256);

    // ------------------------------------------------------------
    // Vault backend interface and concrete implementations
    //
    // [FIX-19] All three use py::smart_holder — required so Python can
    // transfer ownership via std::unique_ptr<IVaultBackend> into ColdVault.
    // ------------------------------------------------------------
    py::class_<IVaultBackend, py::smart_holder>(m, "IVaultBackend");

    py::class_<SimpleFileVaultBackend, IVaultBackend,
               py::smart_holder>(m, "SimpleFileVaultBackend")
        .def(py::init([](const std::string& dir) {
                return std::make_unique<SimpleFileVaultBackend>(
                    std::filesystem::path(dir));
             }),
             py::arg("dir"))
        .def("append_line",    &SimpleFileVaultBackend::append_line,    py::arg("line"))
        .def("read_last_line", &SimpleFileVaultBackend::read_last_line)
        .def("read_all",       &SimpleFileVaultBackend::read_all)
        .def("rotate",         &SimpleFileVaultBackend::rotate);

    py::class_<FileVaultBackend, IVaultBackend,
               py::smart_holder>(m, "FileVaultBackend")
        .def(py::init([](const std::string& path,
                         bool fsync_on_write,
                         IStrongClock& clock) {
                return std::make_unique<FileVaultBackend>(
                    std::filesystem::path(path), fsync_on_write, clock);
             }),
             py::arg("path"),
             py::arg("fsync_on_write") = false,
             py::arg("strong_clock"))
        .def("append_line",    &FileVaultBackend::append_line,    py::arg("line"))
        .def("read_last_line", &FileVaultBackend::read_last_line)
        .def("rotate",         &FileVaultBackend::rotate);

    // ------------------------------------------------------------
    // ColdVault and its configuration
    // ------------------------------------------------------------
    py::class_<ColdVault::Config>(m, "ColdVaultConfig")
        .def(py::init<>())
        .def(py::init([](const std::string& base_dir) {
                ColdVault::Config cfg;
                cfg.base_directory = std::filesystem::path(base_dir);
                return cfg;
             }),
             py::arg("base_directory"))
        .def_readwrite("base_directory",      &ColdVault::Config::base_directory)
        .def_readwrite("max_file_size_bytes", &ColdVault::Config::max_file_size_bytes)
        .def_readwrite("max_file_age_seconds",&ColdVault::Config::max_file_age_seconds)
        .def_readwrite("fsync_on_write",      &ColdVault::Config::fsync_on_write);

    py::class_<ColdVault>(m, "ColdVault")
        .def(py::init<ColdVault::Config,
                      std::unique_ptr<IVaultBackend>,
                      IStrongClock&,
                      IHashProvider&>(),
             py::arg("config"),
             py::arg("backend"),
             py::arg("strong_clock"),
             py::arg("hash_provider"))
        .def("log_security_event",   &ColdVault::log_security_event,
             py::arg("event_key"), py::arg("detail"))
        .def("log_sync_event",       &ColdVault::log_sync_event,      // [FIX-17]
             py::arg("agreed_time"), py::arg("drift_step"), py::arg("current_drift"))
        .def("log_key_rotation_event",&ColdVault::log_key_rotation_event,
             py::arg("key_version"), py::arg("unix_time"))
        .def("save_last_drift",      &ColdVault::save_last_drift,
             py::arg("drift_seconds"))
        .def("load_last_drift",      &ColdVault::load_last_drift)
        .def("save_authority_sequences", &ColdVault::save_authority_sequences,
             py::arg("sequences"))
        .def("load_authority_sequences", &ColdVault::load_authority_sequences);

    // ------------------------------------------------------------
    // [FIX-21] BftSyncResult
    //
    // update_and_sync() returns std::optional<BftSyncResult>. pybind11
    // maps std::optional<T> to T|None in Python, but T must be a registered
    // type. Without this binding every call to update_and_sync() raises:
    //   "Unable to convert function return value to a Python type!
    //    Unregistered type: uml001::BftSyncResult"
    //
    // Must be declared BEFORE BFTQuorumTrustedClock so the type is known
    // when the update_and_sync method binding is registered.
    // ------------------------------------------------------------
    py::class_<BftSyncResult>(m, "BftSyncResult")
        .def(py::init<>())
        .def_readwrite("agreed_time",      &BftSyncResult::agreed_time,
             "Consensus unix timestamp agreed by the quorum.")
        .def_readwrite("applied_drift",    &BftSyncResult::applied_drift,
             "Drift adjustment applied this round (seconds).")
        .def_readwrite("accepted_sources", &BftSyncResult::accepted_sources,
             "Number of observations accepted into the quorum.")
        .def_readwrite("outliers_ejected", &BftSyncResult::outliers_ejected,
             "Number of observations rejected as Byzantine outliers.")
        .def_readwrite("rejected_sources", &BftSyncResult::rejected_sources,
             "Number of observations rejected for other reasons "
             "(bad signature, replay, unknown authority).")
        .def("__repr__", [](const BftSyncResult& r) {
            return "<BftSyncResult agreed_time=" + std::to_string(r.agreed_time) +
                   " applied_drift=" + std::to_string(r.applied_drift) +
                   " accepted=" + std::to_string(r.accepted_sources) +
                   " outliers=" + std::to_string(r.outliers_ejected) +
                   " rejected=" + std::to_string(r.rejected_sources) + ">";
        });

    // ------------------------------------------------------------
    // BFT quorum trusted clock
    // ------------------------------------------------------------
    py::class_<BFTQuorumTrustedClock>(m, "BFTQuorumTrustedClock")
        .def(py::init<BftClockConfig,
                      std::unordered_set<std::string>,
                      ColdVault&>(),
             py::arg("config"),
             py::arg("authorities"),
             py::arg("vault"))
        .def("now_unix",          &BFTQuorumTrustedClock::now_unix)
        .def("get_current_drift", &BFTQuorumTrustedClock::get_current_drift)
        .def("update_and_sync",   &BFTQuorumTrustedClock::update_and_sync,
             py::arg("observations"), py::arg("warp_score") = 0.0)
        .def("verify_observation",&BFTQuorumTrustedClock::verify_observation,
             py::arg("observation"))                                    // [FIX-11]
        .def("apply_shared_state",&BFTQuorumTrustedClock::apply_shared_state,
             py::arg("shared_agreed_time"),
             py::arg("shared_applied_drift"),
             py::arg("leader_system_time_at_sync"),
             py::arg("signature_hex"),
             py::arg("leader_id"),
             py::arg("key_id"),
             py::arg("warp_score") = 0.0);

    // ------------------------------------------------------------
    // NTP observation fetcher
    // ------------------------------------------------------------
    py::class_<NtpServerEntry>(m, "NtpServerEntry")
        .def(py::init<>())
        .def_readwrite("hostname",   &NtpServerEntry::hostname)
        .def_readwrite("max_rtt_ms", &NtpServerEntry::max_rtt_ms)
        .def_readwrite("timeout_ms", &NtpServerEntry::timeout_ms);

    py::class_<NtpObservationFetcher>(m, "NtpObservationFetcher")
        .def(py::init<std::string,
                      std::string,
                      std::vector<NtpServerEntry>,
                      uint8_t,
                      size_t,
                      uint64_t>(),
             py::arg("hmac_key"),
             py::arg("key_id"),
             py::arg("servers"),
             py::arg("stratum_max"),
             py::arg("quorum_size"),
             py::arg("outlier_threshold_s") = 2)
        .def("fetch",               &NtpObservationFetcher::fetch)
        .def("set_hmac_key",        &NtpObservationFetcher::set_hmac_key,
             py::arg("new_hmac_key"), py::arg("new_key_id"))
        .def("save_sequence_state", &NtpObservationFetcher::save_sequence_state);

    // ------------------------------------------------------------
    // Vault logger hooks
    // ------------------------------------------------------------
    m.def("set_vault_logger", &uml001::set_vault_logger, py::arg("sink"));
    m.def("vault_log",        &uml001::vault_log,
          py::arg("key"), py::arg("value"));
}