"""AI analyst read-only (KE-HOACH-SHIELD-2.0.md Phase 2).

Ranh giới của gói này, ép bằng test chứ không bằng lời hứa:

- `shield.ai` KHÔNG được import `shield.privileged` hay `shield.security.response`.
- Tắt AI không được làm giảm detection hiện có.
- Model là một investigator KHÔNG đáng tin: output đi qua validator tất định
  trước khi tới bất cứ đâu khác.
"""

from shield.ai.contracts import (
    Hypothesis,
    InvestigationRequest,
    InvestigationResult,
    SchemaViolation,
)

__all__ = ["Hypothesis", "InvestigationRequest", "InvestigationResult", "SchemaViolation"]
