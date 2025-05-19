from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel
import httpx
from typing import List, Optional
import os
from dotenv import load_dotenv

load_dotenv()

# Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
JWKS_URL = os.getenv("JWKS_URL")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
)

class TokenData(BaseModel):
    sub: str
    exp: int
    realm_access: dict
    preferred_username: str
    email: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    roles: List[str]
    is_active: bool = True

async def get_jwks() -> dict:
    """Fetch JWKS from Keycloak server"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not fetch JWKS from Keycloak"
            ) from e

def get_rsa_key(jwks: dict, unverified_header: dict) -> dict:
    """Extract the RSA key from JWKS that matches the token's kid"""
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            return {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
                "alg": key["alg"]
            }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No matching RSA key found in JWKS"
    )

async def decode_token(token: str) -> TokenData:
    """Decode and validate JWT token"""
    try:
        unverified_header = jwt.get_unverified_header(token)
        jwks = await get_jwks()
        rsa_key = get_rsa_key(jwks, unverified_header)
        
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[rsa_key["alg"]],
            audience=CLIENT_ID,
            options={"verify_aud": True}
        )
        return TokenData(**payload)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Dependency to get current authenticated user"""
    try:
        token_data = await decode_token(token)
        
        if not token_data.sub:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return User(
            username=token_data.preferred_username,
            email=token_data.email,
            first_name=token_data.given_name,
            last_name=token_data.family_name,
            roles=token_data.realm_access.get("roles", [])
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e

def validate_role(required_role: str):
    """Dependency factory to validate user roles"""
    def role_validator(user: User = Depends(get_current_user)):
        if required_role not in user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' is required to access this resource"
            )
        return user
    return role_validator

# Role-specific dependencies
get_admin_user = validate_role("admin")
get_teacher_user = validate_role("enseignant")
get_student_user = validate_role("etudiant")