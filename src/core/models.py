from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class ValidationState(str, Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    ERROR = 'ERROR'
    SKIPPED = 'SKIPPED'
    NOT_APPLICABLE = 'NOT_APPLICABLE'

class GateAction(str, Enum):
    ALLOW = 'ALLOW'
    WARN = 'WARN'
    BLOCK = 'BLOCK'

class ValidatorResult(BaseModel):
    validator_name: str
    state: ValidationState
    findings_count: int = 0
    error_message: Optional[str] = None
    details: List[Dict[str, Any]] = Field(default_factory=list)

class GateDecision(BaseModel):
    run_id: str
    action: GateAction
    reasons: List[str]
    results: List[ValidatorResult]
