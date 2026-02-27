import ctypes
from dataclasses import dataclass

# Define the C-compatible struct for Python
class C_SemanticScore(ctypes.Structure):
    _fields_ = [
        ("authority", ctypes.c_float),
        ("sensitivity", ctypes.c_float),
        ("auth_conf", ctypes.c_float),
        ("sens_conf", ctypes.c_float),
    ]

# Load the compiled C++ library
lib = ctypes.CDLL("./libuml_classifier.so")
lib.score_payload.restype = C_SemanticScore
lib.score_payload.argtypes = [ctypes.c_char_p, ctypes.c_uint64]

def get_fast_score(payload: str):
    now = int(time.time())
    # Call the C++ engine
    result = lib.score_payload(payload.encode('utf-8'), now)
    return {
        "authority": result.authority,
        "sensitivity": result.sensitivity,
        "confidence": (result.auth_conf + result.sens_conf) / 2
    }

# --- 1. Mapping the Hardened C++ Structures ---

class TrustCriteria(BaseModel):
    min_authority_confidence: float = 0.8
    min_sensitivity_confidence: float = 0.8

class ScopeCriteria(BaseModel):
    authority_min: Optional[float] = None
    authority_max: Optional[float] = None
    sensitivity_min: Optional[float] = None
    sensitivity_max: Optional[float] = None

class PolicyRule(BaseModel):
    rule_id: str
    description: str
    trust: TrustCriteria = TrustCriteria()
    scope: ScopeCriteria
    action: str = "DENY"  # Fail-safe default

# --- 2. Sidecar Logic & Engine ---

# app = FastAPI(title="UML-001 Hardened Sidecar")

# Global Configuration (The Compatibility Pillar)
REGISTRY_VERSION = "v2.0.26-ALPHA"

# Sample Hardened Policy
POLICY_STORE: List[PolicyRule] = [
    PolicyRule(
        rule_id="admin-filesystem-access",
        description="Allow high-authority agents to modify files",
        trust=TrustCriteria(min_authority_confidence=0.9, min_sensitivity_confidence=0.9),
        scope=ScopeCriteria(authority_min=0.7, sensitivity_max=0.5),
        action="ALLOW"
    )
]

def evaluate_hardened_policy(score, registry_ver: str) -> dict:
    # Pillar 1: Compatibility Check
    if registry_ver != REGISTRY_VERSION:
        return {"action": "DENY", "reason": "COMPATIBILITY_MISMATCH"}

    for rule in POLICY_STORE:
        # Pillar 2: Trustworthiness Check
        if (score["auth_conf"] < rule.trust.min_authority_confidence or 
            score["sens_conf"] < rule.trust.min_sensitivity_confidence):
            continue # Confidence too low for this rule

        # Pillar 3: Privilege Scope Check
        s = rule.scope
        in_scope = True
        if s.authority_min is not None and score["authority"] < s.authority_min: in_scope = False
        if s.authority_max is not None and score["authority"] > s.authority_max: in_scope = False
        if s.sensitivity_min is not None and score["sensitivity"] < s.sensitivity_min: in_scope = False
        if s.sensitivity_max is not None and score["sensitivity"] > s.sensitivity_max: in_scope = False

        if in_scope:
            return {"action": rule.action, "rule_id": rule.rule_id}

    # Default to Deny
    return {"action": "DENY", "reason": "NO_MATCHING_RULE_FAIL_SAFE"}

# --- 3. API Endpoints ---

class SecurityCheckRequest(BaseModel):
    payload: str
    registry_version: str

@app.post("/check")
async def security_checkpoint(request: SecurityCheckRequest):
    # Calling the C++ Classifier (from previous turn)
    # result = lib.score_payload(request.payload.encode(), int(time.time()))
    
    # Mocked score result for demonstration based on the new C++ struct
    mock_score = {
        "authority": 0.85, 
        "sensitivity": 0.4, 
        "auth_conf": 0.95, 
        "sens_conf": 0.92
    }

    decision = evaluate_hardened_policy(mock_score, request.registry_version)

    if decision["action"] == "DENY":
        raise HTTPException(status_code=403, detail=decision.get("reason", "Policy Violation"))

    return decision