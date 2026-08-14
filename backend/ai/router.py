from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import User, Scan, Vulnerability, ChatMessage
from backend.schemas import ChatQuery, ChatMessageResponse, VulnerabilityDetail
from backend.auth.jwt import get_current_user
from backend.ai.ollama_client import ollama_client
from typing import List

router = APIRouter(prefix="/ai", tags=["AI Security Assistant"])

def get_current_active_paid_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("admin", "paid", "developer", "user", "member"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI features are only available to authenticated accounts."
        )
    return current_user

@router.post("/chat/{scan_id}", response_model=ChatMessageResponse)
async def chat_about_scan(
    scan_id: int,
    query: ChatQuery,
    current_user: User = Depends(get_current_active_paid_or_admin),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
        
    # Check if project belongs to user (or is admin)
    if scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    # Save User message
    user_msg = ChatMessage(
        scan_id=scan.id,
        user_id=current_user.id,
        message=query.message,
        is_ai=False
    )
    db.add(user_msg)
    db.commit()
    db.refresh(user_msg)

    # Gather Code Context (if vulnerability is selected)
    code_context = ""
    if query.vulnerability_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == query.vulnerability_id).first()
        if vuln and vuln.scan_id == scan_id:
            code_context = (
                f"File: {vuln.file_path}\n"
                f"Severity: {vuln.severity}\n"
                f"Category: {vuln.category}\n"
                f"Message: {vuln.message}\n"
                f"Snippet:\n{vuln.code_snippet or ''}"
            )

    # Get Chat History for this scan
    chat_history = db.query(ChatMessage).filter(ChatMessage.scan_id == scan.id).order_by(ChatMessage.created_at.asc()).all()
    # Limit history to last 10 messages to keep prompt size small
    chat_history = chat_history[-10:]

    # Fetch AI response
    ai_reply = await ollama_client.chat_about_scan(chat_history, query.message, code_context)

    # Save AI message
    ai_msg = ChatMessage(
        scan_id=scan.id,
        user_id=current_user.id,  # references this user's chat session
        message=ai_reply,
        is_ai=True
    )
    db.add(ai_msg)
    db.commit()
    db.refresh(ai_msg)

    try:
        from backend.database import get_mongo_db, is_mongo_connected
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.chat_messages.insert_many([
                    {
                        "message_id": user_msg.id,
                        "scan_id": scan.id,
                        "user_id": current_user.id,
                        "message": user_msg.message,
                        "is_ai": False,
                        "created_at": user_msg.created_at
                    },
                    {
                        "message_id": ai_msg.id,
                        "scan_id": scan.id,
                        "user_id": current_user.id,
                        "message": ai_msg.message,
                        "is_ai": True,
                        "created_at": ai_msg.created_at
                    }
                ])
    except Exception:
        pass

    return ai_msg

@router.get("/chat/{scan_id}", response_model=List[ChatMessageResponse])
def get_chat_history(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
        
    if scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
        
    messages = db.query(ChatMessage).filter(ChatMessage.scan_id == scan_id).order_by(ChatMessage.created_at.asc()).all()
    return messages

@router.post("/enrich/{vulnerability_id}", response_model=VulnerabilityDetail)
async def enrich_vulnerability(
    vulnerability_id: int,
    current_user: User = Depends(get_current_active_paid_or_admin),
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
        
    # Check authorization
    if vuln.scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
        
    # If already enriched, just return it
    if vuln.ai_explanation:
        return vuln
        
    # Perform enrichment
    enrichment = await ollama_client.explain_vulnerability(
        vuln.category, vuln.message, vuln.code_snippet or ""
    )
    
    vuln.ai_explanation = enrichment.get("explanation")
    vuln.ai_fix = enrichment.get("fix")
    db.commit()
    db.refresh(vuln)
    
    return vuln
