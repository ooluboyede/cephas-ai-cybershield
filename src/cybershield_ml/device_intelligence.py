"""Human-governed device intelligence and risk recommendations.

This module evaluates customer-scoped, pseudonymous device associations. It does
not execute blocks, change access, or call enforcement systems.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .contracts import TrustedProductScope

AssociationStatus = Literal["suspected", "confirmed", "cleared"]
RecommendationAction = Literal[
    "monitor", "flag", "step_up", "investigate", "block_recommended"
]
ReviewDecision = Literal["approve", "reject"]


class DeviceFraudAssociation(BaseModel):
    """One case-linked association; raw device identifiers must never be supplied."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    deployment_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(min_length=1, max_length=64)
    product_id: str = Field(min_length=1, max_length=96)
    business_unit_id: str | None = Field(default=None, max_length=128)
    device_key: str = Field(pattern=r"^hmac-sha256:v[1-9][0-9]*:[a-f0-9]{64}$")
    case_id: str = Field(min_length=1, max_length=128)
    association_status: AssociationStatus
    evidence_ref: str = Field(min_length=1, max_length=256)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("association timestamps must include a timezone")
        return value.astimezone(timezone.utc)


class DeviceRiskPolicy(BaseModel):
    """Customer-configured policy; defaults are conservative and not universal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lookback_days: int = Field(default=90, ge=1, le=365)
    confirmed_cases_for_block_recommendation: int = Field(default=2, ge=2, le=100)
    minimum_distinct_evidence_refs: int = Field(default=2, ge=1, le=100)


class DeviceRiskContext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    trusted_scope: TrustedProductScope
    product_id: str = Field(min_length=1, max_length=96)
    device_key: str = Field(pattern=r"^hmac-sha256:v[1-9][0-9]*:[a-f0-9]{64}$")
    associations: tuple[DeviceFraudAssociation, ...] = ()
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class DeviceRiskRecommendation(BaseModel):
    """A triage recommendation, never an enforcement command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    deployment_id: str
    environment: str
    product_id: str
    business_unit_id: str | None
    device_key: str
    action: RecommendationAction
    status: Literal["pending_human_review"] = "pending_human_review"
    confirmed_case_count: int = Field(ge=0)
    suspected_case_count: int = Field(ge=0)
    evidence_refs: tuple[str, ...] = ()
    explanation: str
    enforcement_executed: Literal[False] = False


class DeviceRiskReview(BaseModel):
    """Immutable human review record; approval does not execute enforcement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    recommendation_device_key: str
    reviewer_id: str = Field(min_length=1, max_length=128)
    decision: ReviewDecision
    rationale: str = Field(min_length=8, max_length=1024)
    reviewed_at: datetime
    approved_action: Literal["block"] | None = None
    enforcement_executed: Literal[False] = False

    @field_validator("reviewed_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("review timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def decision_consistency(self):
        if self.decision == "approve" and self.approved_action is None:
            raise ValueError("approved reviews must name the approved action")
        if self.decision == "reject" and self.approved_action is not None:
            raise ValueError("rejected reviews cannot approve an action")
        return self


def recommend_device_action(
    context: DeviceRiskContext,
    policy: DeviceRiskPolicy | None = None,
) -> DeviceRiskRecommendation:
    """Evaluate repeated fraud associations within the authenticated deployment."""
    policy = policy or DeviceRiskPolicy()
    scope = context.trusted_scope

    if context.product_id not in scope.allowed_products:
        raise ValueError("device product is not authorised for this deployment")

    recent: list[DeviceFraudAssociation] = []
    seen_cases: set[str] = set()
    for item in context.associations:
        if (
            item.tenant_id != scope.tenant_id
            or item.deployment_id != scope.deployment_id
            or item.environment != scope.environment
            or item.product_id != context.product_id
            or item.business_unit_id != scope.business_unit_id
            or item.device_key != context.device_key
        ):
            raise ValueError("device association is outside the authenticated scope")
        if item.case_id in seen_cases:
            raise ValueError("duplicate case association; deduplicate before evaluation")
        seen_cases.add(item.case_id)
        if item.occurred_at > context.evaluated_at:
            raise ValueError("future-dated device association is not accepted")
        if item.occurred_at >= context.evaluated_at - timedelta(days=policy.lookback_days):
            recent.append(item)

    confirmed = [item for item in recent if item.association_status == "confirmed"]
    suspected = [item for item in recent if item.association_status == "suspected"]
    evidence_refs = tuple(sorted({item.evidence_ref for item in confirmed}))

    if (
        len(confirmed) >= policy.confirmed_cases_for_block_recommendation
        and len(evidence_refs) >= policy.minimum_distinct_evidence_refs
    ):
        action: RecommendationAction = "block_recommended"
        explanation = (
            "Repeated confirmed fraud associations meet the customer-configured "
            "review threshold. Blocking is recommended for authorised human review only."
        )
    elif confirmed:
        action = "investigate"
        explanation = (
            "At least one confirmed fraud association exists, but the configured "
            "block-recommendation threshold is not met."
        )
    elif suspected:
        action = "flag"
        explanation = (
            "Only suspected associations are present. Flag for review; do not block."
        )
    else:
        action = "monitor"
        explanation = "No recent suspected or confirmed fraud association was found."

    return DeviceRiskRecommendation(
        tenant_id=scope.tenant_id,
        deployment_id=scope.deployment_id,
        environment=scope.environment,
        product_id=context.product_id,
        business_unit_id=scope.business_unit_id,
        device_key=context.device_key,
        action=action,
        confirmed_case_count=len(confirmed),
        suspected_case_count=len(suspected),
        evidence_refs=evidence_refs,
        explanation=explanation,
    )


def record_device_risk_review(
    recommendation: DeviceRiskRecommendation,
    *,
    reviewer_id: str,
    decision: ReviewDecision,
    rationale: str,
    reviewed_at: datetime,
) -> DeviceRiskReview:
    """Record a human decision without performing a block or other enforcement."""
    approved_action = (
        "block"
        if decision == "approve" and recommendation.action == "block_recommended"
        else None
    )
    if decision == "approve" and approved_action is None:
        raise ValueError("only a block recommendation can be approved for blocking")
    return DeviceRiskReview(
        recommendation_device_key=recommendation.device_key,
        reviewer_id=reviewer_id,
        decision=decision,
        rationale=rationale,
        reviewed_at=reviewed_at,
        approved_action=approved_action,
        enforcement_executed=False,
    )
