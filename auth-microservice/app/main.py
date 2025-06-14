# from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter
# from fastapi.security import OAuth2PasswordBearer
# from fastapi.middleware.cors import CORSMiddleware
# from jose import jwt, JWTError
# from pydantic import BaseModel
# from typing import List
# import httpx
# import os
# from dotenv import load_dotenv
# # from dependencies import get_current_user, User
# from starlette.status import HTTP_401_UNAUTHORIZED
# import requests

# # Load environment variables
# load_dotenv()

# # Initialize FastAPI app
# app = FastAPI()

# # CORS Setup
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:8001"],  # Your frontend URL
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
#     expose_headers=["*"]
# )


# # Configuration from environment
# KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
# REALM = os.getenv("KEYCLOAK_REALM")
# CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
# JWKS_URL = os.getenv("JWKS_URL")
# #------------
# APP_SECRET_KEY = os.getenv("SECRET_KEY")
# ALGORITHM = os.getenv("ALGORITHM", "RS256")


# class TokenData(BaseModel):
#     user_id: str
#     email: str
#     roles: list[str]



# router = APIRouter()


# class TokenData(BaseModel):
#     sub: str
#     email: str = None
#     name: str = None

# @router.post("/verify-token", response_model=TokenData)
# async def verify_token(request: Request):
#     auth = request.headers.get("Authorization")
#     if not auth or not auth.startswith("Bearer "):
#         raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Missing token")

#     token = auth.split(" ")[1]

#     try:
#         # Get JWKS from Keycloak
#         jwks = requests.get(JWKS_URL).json()
#         unverified_header = jwt.get_unverified_header(token)

#         # Find the right public key
#         rsa_key = {}
#         for key in jwks["keys"]:
#             if key["kid"] == unverified_header["kid"]:
#                 rsa_key = {
#                     "kty": key["kty"],
#                     "kid": key["kid"],
#                     "use": key["use"],
#                     "n": key["n"],
#                     "e": key["e"]
#                 }
#                 break

#         if not rsa_key:
#             raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unable to find appropriate key")

#         payload = jwt.decode(token, rsa_key, algorithms=[ALGORITHM], audience="account")
#         return {
#             "sub": payload.get("sub"),
#             "email": payload.get("email"),
#             "name": payload.get("name"),
#             "roles": roles
#         }
#     except jwt.JWTError as e:
#         raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}")



# # Validate essential configs
# for var in ["KEYCLOAK_SERVER_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "JWKS_URL"]:
#     if not os.getenv(var):
#         raise RuntimeError(f"Environment variable {var} is not set!")

# # OAuth2 scheme
# oauth2_scheme = OAuth2PasswordBearer(
#     tokenUrl=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
# )

# # Pydantic models
# class TokenData(BaseModel):
#     sub: str
#     exp: int
#     realm_access: dict
#     preferred_username: str

# class User(BaseModel):
#     username: str
#     roles: List[str]

# # Fetch JWKS keys
# async def get_jwks():
#     try:
#         async with httpx.AsyncClient() as client:
#             response = await client.get(JWKS_URL)
#             response.raise_for_status()
#             return response.json()
#     except httpx.HTTPError as e:
#         raise HTTPException(
#             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
#             detail=f"Unable to fetch JWKS: {str(e)}"
#         )

# # Extract and validate user from JWT token
# async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

#     try:
#         jwks = await get_jwks()
#         header = jwt.get_unverified_header(token)

#         # Find matching key
#         rsa_key = next(({
#             "kty": key["kty"],
#             "kid": key["kid"],
#             "use": key["use"],
#             "n": key["n"],
#             "e": key["e"],
#             "alg": key["alg"]
#         } for key in jwks["keys"] if key["kid"] == header["kid"]), None)

#         if not rsa_key:
#             raise credentials_exception

#         # Decode and verify token
#         payload = jwt.decode(
#             token,
#             rsa_key,
#             algorithms=[rsa_key["alg"]],
#             audience="account",
#             options={"verify_aud": False}  # set True in production
#         )

#         token_data = TokenData(**payload)

#         return User(
#             username=token_data.preferred_username,
#             roles=token_data.realm_access.get("roles", [])
#         )

#     except JWTError as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"JWT validation error: {str(e)}"
#         )

# # Root endpoint
# @app.get("/")
# async def root():
#     return {"message": "Auth Service is running"}

# # Protected route for any authenticated user
# @app.get("/protected")
# async def protected_route(user: User = Depends(get_current_user)):
#     return {"message": f"Hello {user.username}", "roles": user.roles}

# # Admin-only route
# @app.get("/admin")
# async def admin_route(user: User = Depends(get_current_user)):
#     if "admin" not in user.roles:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Admin access required"
#         )
#     return {"message": f"Welcome admin {user.username}"}

# # Teacher-only route
# @app.get("/teacher")
# async def teacher_route(user: User = Depends(get_current_user)):
#     if "enseignant" not in user.roles:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Teacher access required"
#         )
#     return {"message": f"Welcome teacher {user.username}"}

# # Student-only route
# @app.get("/student")
# async def student_route(user: User = Depends(get_current_user)):
#     if "etudiant" not in user.roles:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Student access required"
#         )
#     return {"message": f"Welcome student {user.username}"}


# @app.get("/users/me", response_model=User)
# async def read_users_me(current_user: User = Depends(get_current_user)):
#     """
#     Returns the currently authenticated user's information.
#     """
#     return current_user


# app.include_router(router)
# #app.include_router(router, prefix="/auth")


from fastapi import FastAPI, Depends, HTTPException, status, Request, APIRouter
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from pydantic import BaseModel
from typing import List
import httpx
import os
from dotenv import load_dotenv
from starlette.status import HTTP_401_UNAUTHORIZED

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# CORS Setup
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:3000",
#         "http://localhost:3001",
#         "http://localhost:8000",  # Add Keycloak callback
#         "http://localhost:8001",

#         "http://127.0.0.1:8000",  # Add Keycloak callback
#         "http://127.0.0.1:8001", # Ensure FastAPI itself # Ensure FastAPI itself
#         "http://127.0.0.1:3000",
#         "http://127.0.0.1:3001",

#         "http://192.168.1.30:3000",
#         "http://192.168.1.30:3001",
#         "http://192.168.1.30:8000",  # Add Keycloak callback
#         "http://192.168.1.30:8001" 
#         ],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
#     expose_headers=["*"]
# )

# Configuration from environment
# KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL")
# REALM = os.getenv("KEYCLOAK_REALM")
# CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
# JWKS_URL = os.getenv("JWKS_URL")
# ALGORITHM = os.getenv("ALGORITHM", "RS256")
KEYCLOAK_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "est-realm")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "est-client")
JWKS_URL = os.getenv("JWKS_URL", f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs")
ALGORITHM = os.getenv("ALGORITHM", "RS256")


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
    email: str = None
    name: str = None
    roles: List[str] = []
    exp: int = None
    realm_access: dict = None
    preferred_username: str = None

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
            audience="account",
            options={"verify_aud": False}  # Set True in production
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

# Router for token verification
router = APIRouter()

@router.post("/verify-token", response_model=TokenData)
async def verify_token(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Missing token")

    token = auth.split(" ")[1]

    try:
        # Get JWKS from Keycloak
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()

        unverified_header = jwt.get_unverified_header(token)

        # Find the right public key
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
                break

        if not rsa_key:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unable to find appropriate key")

        # Decode the token
        payload = jwt.decode(token, rsa_key, algorithms=[ALGORITHM], audience="account")
        roles = payload.get("realm_access", {}).get("roles", [])

        return TokenData(
            sub=payload.get("sub"),
            email=payload.get("email"),
            name=payload.get("name"),
            roles=roles
        )
    except (jwt.JWTError, httpx.HTTPError) as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}")


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

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's information.
    """
    return current_user

app.include_router(router)