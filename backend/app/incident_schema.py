"""ケース／インシデント管理機能（設計書v4）のAPIスキーマ。既存 schema.py には手を入れず、
本機能分だけをここに分離する（schema.py は別タスクの未コミット変更が乗っているため）。"""
from typing import Literal

from pydantic import BaseModel

Verdict = Literal["unjudged", "true_positive", "false_positive", "over_detection", "other"]


# ---- イベント ----
class EventResolvedUpdate(BaseModel):
    resolved: bool


# ---- ケース ----
class CaseCreate(BaseModel):
    title: str


class CaseTitleUpdate(BaseModel):
    title: str


class CaseEventAdd(BaseModel):
    event_id: int
    note: str | None = None


class CaseEventNoteUpdate(BaseModel):
    note: str | None = None


class CaseCommentCreate(BaseModel):
    body: str


# ---- インシデント ----
class IncidentStatusUpdate(BaseModel):
    status_id: int


class IncidentAssigneeUpdate(BaseModel):
    assignee_user_id: int | None = None


class IncidentVerdictUpdate(BaseModel):
    verdict: Verdict


class IncidentCommentCreate(BaseModel):
    body: str


class IncidentStatusCreate(BaseModel):
    name: str


class IncidentStatusVisibilityUpdate(BaseModel):
    is_visible: bool


class IncidentResponseActionCreate(BaseModel):
    action_type_id: int
    detail: str | None = None


class IncidentResponseActionTypeCreate(BaseModel):
    name: str


class IncidentResponseActionTypeVisibilityUpdate(BaseModel):
    is_visible: bool
