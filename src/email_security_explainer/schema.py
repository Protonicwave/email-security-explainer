"""The fixed shape a model's explanation of the findings must take."""

from pydantic import BaseModel, ConfigDict, Field

from email_security_explainer.findings import FindingCode, RecordKind


class Claim(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_code: FindingCode = Field(description="The code of the finding this claim explains.")
    record: RecordKind = Field(description="The record the finding is about.")
    quoted_value: str | None = Field(
        description="The finding's evidence token copied exactly, or null when it has none."
    )
    explanation: str = Field(
        description="What the problem lets an impersonator do, in plain English."
    )
    fix: str = Field(description="The change to the record that removes the problem.")


class Explanation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(description="Two or three sentences on the domain's overall exposure.")
    claims: list[Claim] = Field(description="One claim per finding.")
