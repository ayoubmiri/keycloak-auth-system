from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import List
import httpx
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Configuration from environment
KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
REALM = os.getenv("KEYCLOAK_REALM")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
JWKS_URL = os.getenv("JWKS_URL")

# Validate essential configs
for var in ["KEYCLOAK_SERVER_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "JWKS_URL"]:
    if not os.getenv(var):
        raise RuntimeError(f"Environment variable {var} is not set!")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
)

# Pydantic models
class TokenData(BaseModel):
    sub: str
    exp: int
    realm_access: dict
    preferred_username: str

class User(BaseModel):
    username: str
    roles: List[str]

# Fetch JWKS keys
async def get_jwks():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to fetch JWKS: {str(e)}"
        )

# Extract and validate user from JWT token
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        jwks = await get_jwks()
        header = jwt.get_unverified_header(token)

        # Find matching key
        rsa_key = next(({
            "kty": key["kty"],
            "kid": key["kid"],
            "use": key["use"],
            "n": key["n"],
            "e": key["e"],
            "alg": key["alg"]
        } for key in jwks["keys"] if key["kid"] == header["kid"]), None)

        if not rsa_key:
            raise credentials_exception

        # Decode and verify token
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[rsa_key["alg"]],
            audience=CLIENT_ID,
            options={"verify_aud": False}  # set True in production
        )

        token_data = TokenData(**payload)

        return User(
            username=token_data.preferred_username,
            roles=token_data.realm_access.get("roles", [])
        )

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"JWT validation error: {str(e)}"
        )

# Root endpoint
@app.get("/")
async def root():
    return {"message": "Auth Service is running"}

# Protected route for any authenticated user
@app.get("/protected")
async def protected_route(user: User = Depends(get_current_user)):
    return {"message": f"Hello {user.username}", "roles": user.roles}

# Admin-only route
@app.get("/admin")
async def admin_route(user: User = Depends(get_current_user)):
    if "admin" not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return {"message": f"Welcome admin {user.username}"}

# Teacher-only route
@app.get("/teacher")
async def teacher_route(user: User = Depends(get_current_user)):
    if "enseignant" not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Teacher access required"
        )
    return {"message": f"Welcome teacher {user.username}"}

# Student-only route
@app.get("/student")
async def student_route(user: User = Depends(get_current_user)):
    if "etudiant" not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student access required"
        )
    return {"message": f"Welcome student {user.username}"}
