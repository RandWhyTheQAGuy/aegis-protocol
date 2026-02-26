// classifier.h
    #pragma once
    #include "passport.h"   // for sha256_hex
    #include <functional>
    #include <stdexcept>

    namespace uml002 {

    struct SemanticScore {
        std::string payload_hash;
        float       authority             = 0.0f;  // [-1.0, 1.0]
        float       sensitivity           = 0.0f;  // [ 0.0, 1.0]
        float       authority_confidence  = 0.0f;  // [ 0.0, 1.0]
        float       sensitivity_confidence= 0.0f;  // [ 0.0, 1.0]
        std::string classifier_version;
        uint64_t    scored_at             = 0;

        bool is_low_confidence(float threshold = 0.5f) const {
            return authority_confidence   < threshold
                || sensitivity_confidence < threshold;
        }
    };

    // ---------------------------------------------------------------------------
    // ClassifierBackend: function type for the external inference call.
    // Implement this to wrap your actual model inference.
    // Signature: SemanticScore classify(const std::string& payload, uint64_t now)
    // ---------------------------------------------------------------------------
    using ClassifierBackend =
        std::function<SemanticScore(const std::string&, uint64_t)>;

    // ---------------------------------------------------------------------------
    // SemanticClassifier: wraps a backend and adds input validation / logging
    // ---------------------------------------------------------------------------
    class SemanticClassifier {
    public:
        explicit SemanticClassifier(ClassifierBackend backend)
            : backend_(std::move(backend)) {
            if (!backend_)
                throw std::invalid_argument(
                    "SemanticClassifier: backend must not be null");
        }

        SemanticScore score(const std::string& payload, uint64_t now) const {
            if (payload.empty())
                throw std::invalid_argument(
                    "SemanticClassifier: payload must not be empty");

            SemanticScore result = backend_(payload, now);
            result.payload_hash  = sha256_hex(payload);
            result.scored_at     = now;

            validate_score(result);
            return result;
        }

    private:
        ClassifierBackend backend_;

        static void validate_score(const SemanticScore& s) {
            if (s.authority   < -1.0f || s.authority   > 1.0f)
                throw std::runtime_error(
                    "Classifier returned out-of-range authority score");
            if (s.sensitivity <  0.0f || s.sensitivity > 1.0f)
                throw std::runtime_error(
                    "Classifier returned out-of-range sensitivity score");
            if (s.authority_confidence    < 0.0f ||
                s.authority_confidence    > 1.0f ||
                s.sensitivity_confidence  < 0.0f ||
                s.sensitivity_confidence  > 1.0f)
                throw std::runtime_error(
                    "Classifier returned out-of-range confidence score");
        }
    };

    // ---------------------------------------------------------------------------
    // Example stub backend for testing -- replace with real inference call
    // ---------------------------------------------------------------------------
    inline ClassifierBackend make_stub_backend(float fixed_authority  = 0.0f,
                                               float fixed_sensitivity= 0.0f) {
        return [fixed_authority, fixed_sensitivity]
               (const std::string& /*payload*/, uint64_t now) -> SemanticScore {
            SemanticScore s;
            s.authority              = fixed_authority;
            s.sensitivity            = fixed_sensitivity;
            s.authority_confidence   = 0.9f;
            s.sensitivity_confidence = 0.9f;
            s.classifier_version     = "stub-0.1";
            s.scored_at              = now;
            return s;
        };
    }

    } // namespace uml002
