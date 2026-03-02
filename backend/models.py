from pydantic import BaseModel
from typing import Optional


class SummaryResponse(BaseModel):
    total_events: int
    high_severity_count: int
    med_severity_count: int
    unique_pids: int
    unique_processes: int
    monitoring_span_seconds: float
    last_updated: str


class TimelineBucket(BaseModel):
    time: str
    HIGH: int
    MED: int


class TimelineResponse(BaseModel):
    buckets: list[TimelineBucket]


class EventDistributionItem(BaseModel):
    event_name: str
    count: int
    severity: str


class EventDistributionResponse(BaseModel):
    distribution: list[EventDistributionItem]


class TopProcess(BaseModel):
    process_name: str
    pid_count: int
    event_count: int
    high_count: int
    med_count: int
    event_types: list[str]


class TopProcessesResponse(BaseModel):
    processes: list[TopProcess]


class RWXEvent(BaseModel):
    timestamp: str
    pid: int
    ppid: int
    process_name: str
    detail: str


class RWXEventsResponse(BaseModel):
    rwx_events: list[RWXEvent]
    total: int


class ProcessTreeNode(BaseModel):
    pid: int
    process_name: str
    event_count: int
    has_high: bool
    children: list["ProcessTreeNode"] = []


ProcessTreeNode.model_rebuild()


class ProcessTreeResponse(BaseModel):
    trees: list[ProcessTreeNode]


class PerPIDResult(BaseModel):
    pid: int
    process: str
    risk_level: str
    fuzzy_score: int
    rl_action: str
    expected_action: str
    correct: bool
    confidence: float
    baseline: str


class ModelResultsResponse(BaseModel):
    available: bool
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    risk_distribution: Optional[dict[str, int]] = None
    action_distribution: Optional[dict[str, int]] = None
    per_pid: Optional[list[PerPIDResult]] = None


class FeedEvent(BaseModel):
    timestamp: str
    pid: int
    process_name: str
    event_name: str
    severity: str
    detail: str


class EventFeedResponse(BaseModel):
    events: list[FeedEvent]
