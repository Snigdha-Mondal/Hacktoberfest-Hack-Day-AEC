"""Risk Fusion Layer: reconciles and de-duplicates findings across deterministic and AI models."""
from __future__ import annotations

from typing import List, Optional

from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    RiskReport,
)
from app.risk.policy import _RISK_ORDER, determine_overall_risk

_ACTION_ORDER = {
    RecommendedAction.BLACKOUT: 5,
    RecommendedAction.BLUR: 4,
    RecommendedAction.PIXELATE: 3,
    RecommendedAction.CROP: 2,
    RecommendedAction.REVIEW: 1,
    RecommendedAction.NONE: 0,
}


def calculate_iou(box1: BoundingBox, box2: BoundingBox) -> float:
    """Calculate Intersection over Union (IoU) between two BoundingBoxes."""
    x_left = max(box1.x, box2.x)
    y_top = max(box1.y, box2.y)
    x_right = min(box1.x2, box2.x2)
    y_bottom = min(box1.y2, box2.y2)

    if x_right <= x_left or y_bottom <= y_top:
        return 0.0

    intersection_area = (x_right - x_left) * (y_bottom - y_top)
    area1 = box1.width * box1.height
    area2 = box2.width * box2.height
    union_area = float(area1 + area2 - intersection_area)

    if union_area <= 0:
        return 0.0

    return round(intersection_area / union_area, 4)


def boxes_overlap(
    box1: Optional[BoundingBox], box2: Optional[BoundingBox], threshold: float = 0.3
) -> bool:
    """Check if two bounding boxes significantly overlap or if one encloses the other."""
    if box1 is None or box2 is None:
        return False

    iou = calculate_iou(box1, box2)
    if iou >= threshold:
        return True

    # Check containment / high overlap with smaller box
    x_left = max(box1.x, box2.x)
    y_top = max(box1.y, box2.y)
    x_right = min(box1.x2, box2.x2)
    y_bottom = min(box1.y2, box2.y2)

    if x_right > x_left and y_bottom > y_top:
        inter = (x_right - x_left) * (y_bottom - y_top)
        min_area = min(box1.width * box1.height, box2.width * box2.height)
        if min_area > 0 and (inter / float(min_area)) >= 0.65:
            return True

    return False


def _combine_boxes(b1: BoundingBox, b2: BoundingBox) -> BoundingBox:
    """Compute the union bounding box that encloses both."""
    min_x = min(b1.x, b2.x)
    min_y = min(b1.y, b2.y)
    max_x2 = max(b1.x2, b2.x2)
    max_y2 = max(b1.y2, b2.y2)
    return BoundingBox(
        x=min_x,
        y=min_y,
        width=max_x2 - min_x,
        height=max_y2 - min_y,
    )


def merge_findings(f1: Finding, f2: Finding) -> Finding:
    """Merge two overlapping findings into a single high-confidence fused finding."""
    # Determine higher risk
    r1_val = _RISK_ORDER.get(f1.risk, 0)
    r2_val = _RISK_ORDER.get(f2.risk, 0)
    best_risk = f1.risk if r1_val >= r2_val else f2.risk

    # Determine stricter action
    a1_val = _ACTION_ORDER.get(f1.recommended_action, 0)
    a2_val = _ACTION_ORDER.get(f2.recommended_action, 0)
    best_action = f1.recommended_action if a1_val >= a2_val else f2.recommended_action

    # Location union
    if f1.location and f2.location:
        best_location = _combine_boxes(f1.location, f2.location)
    else:
        best_location = f1.location or f2.location

    # Evidence: prefer the one with specific tokens/payload
    ev1 = f1.masked_evidence
    ev2 = f2.masked_evidence
    if "[" in ev2 and "[" not in ev1:
        best_evidence = ev1
    elif "[" in ev1 and "[" not in ev2:
        best_evidence = ev2
    else:
        best_evidence = ev1 if len(ev1) >= len(ev2) else ev2

    # Reason: combine unique reasons
    reason_parts = [f1.reason]
    if f2.reason and f2.reason not in f1.reason:
        reason_parts.append(f2.reason)
    best_reason = " ".join(reason_parts)

    best_conf = max(f1.confidence, f2.confidence)

    return Finding(
        category=f1.category if f1.category != "other" else f2.category,
        label=f1.label if len(f1.label) >= len(f2.label) else f2.label,
        confidence=best_conf,
        risk=best_risk,
        reason=best_reason,
        masked_evidence=best_evidence,
        location=best_location,
        recommended_action=best_action,
        detector_source="fused",
    )


def fuse_findings(
    deterministic_findings: List[Finding],
    model_findings: List[Finding],
    uncertainty_flags: Optional[List[str]] = None,
    original_file_hash: str = "",
) -> RiskReport:
    """Reconcile and merge deterministic findings with AI vision model findings."""
    fused: List[Finding] = []
    matched_model_indices = set()

    flags = list(uncertainty_flags or [])

    # Step 1: Compare each deterministic finding with model findings
    for det_f in deterministic_findings:
        matched = False
        for idx, mod_f in enumerate(model_findings):
            if idx in matched_model_indices:
                continue

            # Merge if categories align and boxes overlap (or if identical category without location)
            categories_match = (
                det_f.category == mod_f.category
                or (det_f.category == "other")
                or (mod_f.category == "other")
            )

            if categories_match and boxes_overlap(det_f.location, mod_f.location):
                merged = merge_findings(det_f, mod_f)
                fused.append(merged)
                matched_model_indices.add(idx)
                matched = True
                break

        if not matched:
            fused.append(det_f)

    # Step 2: Add unmatched model findings
    for idx, mod_f in enumerate(model_findings):
        if idx not in matched_model_indices:
            fused.append(mod_f)

    # Step 3: Determine composite risk & safe to share status
    overall_risk = determine_overall_risk(fused)
    safe = (len(fused) == 0 and overall_risk == RiskLevel.LOW)

    return RiskReport(
        document_type="image",
        overall_risk=overall_risk,
        findings=fused,
        uncertainty_flags=flags,
        safe_to_share_without_changes=safe,
        original_file_hash=original_file_hash,
    )
