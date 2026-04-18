from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.change_event import AlertRule
from app.models.user import User

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertRuleCreate(BaseModel):
    channel: str   # telegram | email
    target: str    # chat_id or email


class AlertRuleOut(BaseModel):
    id: str
    org_id: str
    channel: str
    target: str
    active: bool

    model_config = {"from_attributes": True}


@router.get("/rules", response_model=list[AlertRuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AlertRule).where(AlertRule.org_id == current_user.org_id)
    )
    return result.scalars().all()


@router.post("/rules", response_model=AlertRuleOut, status_code=201)
async def create_rule(
    payload: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rule = AlertRule(
        org_id=current_user.org_id,
        channel=payload.channel,
        target=payload.target,
    )
    db.add(rule)
    await db.flush()
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(AlertRule).where(AlertRule.id == rule_id, AlertRule.org_id == current_user.org_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    await db.delete(rule)
