// consensus.h
    #pragma once
    #include "classifier.h"
    #include <vector>
    #include <algorithm>
    #include <numeric>
    #include <cmath>
    #include <stdexcept>

    namespace uml001 {

    struct AgentScore {
        std::string agent_id;
        SemanticScore score;
    };

    struct ConsensusResult {
        float   authority;          // geometric median authority
        float   sensitivity;        // geometric median sensitivity
        size_t  num_agents;
        size_t  fault_tolerance;    // floor((n-1)/3)
        bool    outlier_detected;   // true if any agent deviated > threshold
        std::vector<std::string> outlier_agent_ids;
    };

    // ---------------------------------------------------------------------------
    // Geometric median in R^2 via Weiszfeld's algorithm
    // ---------------------------------------------------------------------------
    inline std::pair<float, float> geometric_median_2d(
            const std::vector<std::pair<float, float>>& points,
            int iterations = 100,
            float epsilon  = 1e-6f) {

        if (points.empty())
            throw std::invalid_argument("geometric_median_2d: empty input");
        if (points.size() == 1) return points[0];

        // Initial estimate: centroid
        float mx = 0.0f, my = 0.0f;
        for (const auto& p : points) { mx += p.first; my += p.second; }
        mx /= static_cast<float>(points.size());
        my /= static_cast<float>(points.size());

        for (int iter = 0; iter < iterations; ++iter) {
            float num_x = 0.0f, num_y = 0.0f, denom = 0.0f;
            for (const auto& p : points) {
                float dx   = p.first  - mx;
                float dy   = p.second - my;
                float dist = std::sqrt(dx * dx + dy * dy);
                if (dist < epsilon) continue;  // skip coincident points
                float w     = 1.0f / dist;
                num_x      += p.first  * w;
                num_y      += p.second * w;
                denom      += w;
            }
            if (denom < epsilon) break;
            float new_mx = num_x / denom;
            float new_my = num_y / denom;
            if (std::abs(new_mx - mx) < epsilon &&
                std::abs(new_my - my) < epsilon) break;
            mx = new_mx;
            my = new_my;
        }
        return { mx, my };
    }

    // ---------------------------------------------------------------------------
    // BFTConsensusEngine
    // ---------------------------------------------------------------------------
    class BFTConsensusEngine {
    public:
        // Outlier threshold: an agent is flagged if its score deviates from
        // the consensus by more than this Euclidean distance in (auth, sens) space.
        explicit BFTConsensusEngine(float outlier_threshold = 0.3f)
            : outlier_threshold_(outlier_threshold) {}

        ConsensusResult compute(const std::vector<AgentScore>& agent_scores) const {
            if (agent_scores.empty())
                throw std::invalid_argument(
                    "BFTConsensusEngine: no agent scores provided");

            size_t n = agent_scores.size();

            std::vector<std::pair<float,float>> points;
            points.reserve(n);
            for (const auto& as : agent_scores)
                points.emplace_back(as.score.authority, as.score.sensitivity);

            auto [med_auth, med_sens] = geometric_median_2d(points);

            ConsensusResult result;
            result.authority         = med_auth;
            result.sensitivity       = med_sens;
            result.num_agents        = n;
            result.fault_tolerance   = (n - 1) / 3;
            result.outlier_detected  = false;

            for (const auto& as : agent_scores) {
                float da   = as.score.authority  - med_auth;
                float ds   = as.score.sensitivity - med_sens;
                float dist = std::sqrt(da * da + ds * ds);
                if (dist > outlier_threshold_) {
                    result.outlier_detected = true;
                    result.outlier_agent_ids.push_back(as.agent_id);
                }
            }

            return result;
        }

    private:
        float outlier_threshold_;
    };

    } // namespace uml001
