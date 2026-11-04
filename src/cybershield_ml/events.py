from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

EventType = Literal["auth_failure", "auth_success", "network_connection",
                    "process_launch", "privilege_change", "file_activity"]

class SecurityEvent(BaseModel):
    """Normalised input event. Authentication/tenant authorisation happen upstream."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    event_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    entity_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    event_type: EventType
    source_ip: str | None = Field(default=None, max_length=64)
    destination: str | None = Field(default=None, max_length=256)
    outbound_bytes: int = Field(default=0, ge=0)
    process_name: str | None = Field(default=None, max_length=256)
    privileged: bool = False

    @field_validator("timestamp")
    @classmethod
    def aware_utc(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)
