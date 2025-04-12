from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import logging
from app.core.security import verify_token
from app.models.schemas import User

logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Dependency to get the current authenticated user from JWT token
    """
    try:
        payload = verify_token(token)
        username: str = payload.get("sub")
        
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # In a real application, retrieve user from database
        # For this example, we'll create a simplified user object
        permissions = payload.get("permissions", [])
        
        user = User(
            id="user_id_placeholder",
            email="admin@example.com",
            username=username,
            is_active=True,
            is_superuser="admin" in permissions,
            created_at=None  # Would come from database
        )
        
        return user
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Dependency to ensure that the current user is an admin
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user