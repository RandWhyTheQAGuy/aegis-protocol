#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>
#include "classifier.h" // Assuming the header from UML-001 spec

namespace uml001 {

class FastHeuristicEngine {
public:
    // Component 3.1: Scoring Logic
    SemanticScore analyze(const std::string& payload, uint64_t now) {
        SemanticScore score;
        score.payload_hash = sha256_hex(payload);
        score.scored_at = now;
        score.classifier_version = "UML-001-FAST-HEURISTIC-1.0";

        // Initializing base scores
        float auth = 0.0f;
        float sens = 0.1f;

        // Convert to lowercase for matching
        std::string low_payload = payload;
        std::transform(low_payload.begin(), low_payload.end(), low_payload.begin(), ::tolower);

        // Authority Indicators (Positive/Negative)
        if (low_payload.find("sudo") != std::string::npos) auth += 0.5f;
        if (low_payload.find("admin") != std::string::npos) auth += 0.3f;
        if (low_payload.find("please") != std::string::npos) auth -= 0.2f; // Low authority markers

        // Sensitivity Indicators (Risk Magnitude)
        if (low_payload.find("delete") != std::string::npos) sens += 0.4f;
        if (low_payload.find("password") != std::string::npos) sens += 0.7f;
        if (low_payload.find("db_drop") != std::string::npos) sens += 0.9f;

        // Clamping results to UML-001 spec ranges
        score.authority = std::max(-1.0f, std::min(1.0f, auth));
        score.sensitivity = std::max(0.0f, std::min(1.0f, sens));
        
        // High confidence for explicit keyword matches
        score.authority_confidence = 0.85f;
        score.sensitivity_confidence = 0.90f;

        return score;
    }
};

} // namespace uml001

// --- C Linkage for Python Integration ---
extern "C" {
    struct C_SemanticScore {
        float authority;
        float sensitivity;
        float auth_conf;
        float sens_conf;
    };

    // Shared library entry point
    C_SemanticScore score_payload(const char* payload, uint64_t now) {
        static uml001::FastHeuristicEngine engine;
        auto result = engine.analyze(std::string(payload), now);
        
        return { 
            result.authority, 
            result.sensitivity, 
            result.authority_confidence, 
            result.sensitivity_confidence 
        };
    }
}
