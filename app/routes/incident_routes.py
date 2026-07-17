from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


@router.get("/")
def get_incidents(
    current_user: str = Depends(get_current_user)
):
    return {
        "message": "Protected incident data retrived",
        "authenticated_user": current_user,
        "incidents": []
    }