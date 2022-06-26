import json
import re
from datetime import timedelta, datetime
from email.mime.text import MIMEText
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, validator
from starlette import status
from starlette.websockets import WebSocket, WebSocketDisconnect
from tortoise import Tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from redmail import gmail
from db import init, Post, User
from config import *

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await User.get_or_none(id=user_id)
    if user is None:
        raise credentials_exception
    return user


@app.on_event("startup")
async def startup():
    await init()


@app.on_event("shutdown")
async def startup():
    await Tortoise.close_connections()


Post_Pydantic = pydantic_model_creator(Post, exclude=("id", "updated_at", "created_at"))


@app.put("/post")
async def create_post(new_post_pydantic: Post_Pydantic, _: User = Depends(get_current_user)):
    new_post = Post().update_from_dict(new_post_pydantic.dict())
    await new_post.save()


@app.delete("/post")
async def delete_post(post_id: int, _: User = Depends(get_current_user)):
    await Post.filter(id=post_id).delete()


@app.patch("/post")
async def edit_post(post_id: int, post_pydantic: Post_Pydantic, _: User = Depends(get_current_user)):
    post = await Post.get(id=post_id)
    post = post.update_from_dict(post_pydantic.dict())
    await post.save()


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str, websocket: WebSocket):
        for connection in self.active_connections:
            if websocket is not connection:
                await connection.send_text(message)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            print(data)
            post_id = data["postId"]
            new_json = data["body"]
            if new_json is None:
                post = await Post.get(id=post_id)
                await manager.send_personal_message(json.dumps({"postId": post.id, "body": post.body}), websocket)
            else:
                await Post.filter(id=post_id).update(body=new_json)
                await manager.broadcast(json.dumps(data), websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


class Token(BaseModel):
    access_token: str
    token_type: str


@app.post("/auth", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.get_or_none(name=form_data.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"user_id": user.id}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.post("/hash")
async def hash_password(password: str):
    return get_password_hash(password)


class Email(BaseModel):
    phone: Optional[str]
    email: EmailStr
    body: str
    name: str

    @validator("phone")
    def check_phone_format(cls, v):
        if v is None:
            return v
        regexp = r'^\s*(?:\+?(\d{1,3}))?([-. (]*(\d{3})[-. )]*)?((\d{3})[-. ]*(\d{2,4})(?:[-.x ]*(\d+))?)\s*$'
        if not re.search(regexp, v):
            return ValueError("not match")
        return v


gmail.username = FROM_EMAIL
gmail.password = GMAIL_PASSWORD


@app.post("/send_email")
async def send_email(email: Email):
    subject = f'Mail from {email.name}'
    gmail.send(
        subject,
        receivers=[TO_EMAIL],
        text=BODY_TEMPLATE % (email.name, email.email, email.phone, email.body),
    )


class RegisterRequest(BaseModel):
    username: str
    password: str


@app.post("/register")
async def register_handler(request: RegisterRequest):
    await User.create(name=request.username, password=get_password_hash(request.password))


@app.get("/post")
async def get_post(post_id: str):
    return await Post.get(id=post_id)
