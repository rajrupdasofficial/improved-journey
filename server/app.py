from fastapi import Cookie, FastAPI, HTTPException, Request,Depends,status,File, UploadFile, WebSocket
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.hash import bcrypt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from .models import User,Message
from .database import client
import websockets
import jwt
from jose import jwt,JWTError
from decouple import config
from typing import Optional
import asyncio
import os
import base64
import uuid



app = FastAPI()
UPLOAD_DIRECTORY = "uploads"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# jwt config
jwt_secret = config("JWT_SECRET").encode()
bearer_scheme = HTTPBearer()

origins = config("CLIENT_URL")
# enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET","PUT","PATCH","DELETE","POST"],
    allow_headers=["*"],
)

@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile):
    try:
        file_bytes = await file.read()
        file_key = f"{file.filename}"
        s3.upload_fileobj(BytesIO(file_bytes), BUCKET_NAME, file_key)
        file_url = f"https://{BUCKET_NAME}.s3.amazonaws.com/{file_key}"
        return {"file_url": file_url}
    except ClientError as e:
        print(e)
        return {"detail": "Failed to upload file."}
class UserRegistrationRequest(BaseModel):
    username: str
    password: str



def generate_token(user):
    token_payload = {
        "user_id": str(user._id),
        "username": user.username,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jwt.encode(token_payload, jwt_secret, algorithm="HS256")


# test sync
@app.get('/test', tags=["Test"])
async def test():
    return "doubt"


# Register endpoint
@app.post('/register', tags=["Register"])
async def create_user(request: UserRegistrationRequest):
    user = await User.create({"username": request.username, "password": request.password})
    response = JSONResponse(content={"id": str(user._id)})
    token = generate_token(user)
    response.set_cookie(key="token", value=token, httponly=True, samesite="none", secure=True)
    return response

# class User(BaseModel):
#     username: str
#     password_hash: str

#     class Config:
#         orm_mode = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    

# Login endpoint
@app.post('/login', response_model=LoginResponse)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    # find user in database
    # assuming User is a model representing your user collection/table
    find_user = await User.find_one({"username": form_data.username})

    if find_user:
        # extract password hash from the dictionary object
        password_hash = find_user.get("password_hash")

        # check if password matches
        pass_ok = bcrypt.verify(form_data.password, password_hash)

        if pass_ok:
            # generate and return JWT token
            token_payload = {"user_id": str(find_user["_id"]), "username": form_data.username}
            token = jwt.encode(token_payload, jwt_secret, algorithm="HS256")
            response = LoginResponse(access_token=token, token_type="bearer", username=form_data.username)
            return response
        else:
            raise HTTPException(status_code=401, detail="Incorrect username or password")
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")



# user profile section
@app.get("/profile")
async def profile(token: Optional[str] = Cookie(default=None)):
    if not token:
        raise HTTPException(status_code=401, detail="No token")
    
    try:
        payload = jwt.decode(token, jwt_secret, algorithms="HS256")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return JSONResponse(content=payload)


async def get_user_data_from_request(request: Request):
    credentials: HTTPAuthorizationCredentials = bearer_scheme(request)
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    try:
        token_payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        return {"user_id": token_payload["user_id"], "username": token_payload["username"]}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Messages endpoint
@app.get('/messages/{userId}')
async def messages(userId: str, token: str = Depends(oauth2_scheme)):
    # get user id from token payload
    payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    our_user_id = payload.get('user_id')

    messages = await db['messages'].find({
        "sender": {"$in": [userId, our_user_id]},
        "recipient": {"$in": [userId, our_user_id]},
    }).sort("created_at", 1)

    return [Message(**msg) for msg in messages]

@app.get('/people')
async def get_people():
    users = await users_collection.find({}, {'_id':1,'username':1}).to_list(length=None)
    return users

async def notify_about_online_people():
    online_users = []
    for client in connected_clients:
        online_users.append({"userId": client["userId"], "username": client["username"]})
    message = {"online": online_users}
    for client in connected_clients:
        await client["websocket"].send(json.dumps(message))

async def start_ping(websocket: websockets.WebSocketClientProtocol):
    while websocket.open:
        try:
            await websocket.ping()
            await asyncio.sleep(5)
        except:
            websocket.open = False
            await websocket.close()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, request: Request,current_user: User = Depends(get_user_data_from_request),response_model=None):

    websocket.is_alive = True
    websocket.open = True
    websocket.timer = asyncio.create_task(start_ping(websocket))
    websocket.username = None
    websocket.userId = None
    connected_clients.append({"websocket": websocket, "userId": None, "username": None})

    # read username and id form the cookie for this connection
    cookies = request.headers.get("cookie")
    if cookies:
        token_cookie = None
        cookie_parts = cookies.split(";")
        for cookie_part in cookie_parts:
            cookie_part = cookie_part.strip()
            if cookie_part.startswith("token="):
                token_cookie = cookie_part
                break
        if token_cookie:
            token = token_cookie.split("=")[1]
            try:
                token_payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
                websocket.userId = token_payload["user_id"]
                websocket.username = token_payload["username"]
            except jwt.PyJWTError:
                raise HTTPException(status_code=401, detail="Invalid token")

    async for message in websocket:
        try:
            message_data = json.loads(message)
            recipient = message_data["recipient"]
            text = message_data.get("text")
            file_data = message_data.get("file")
            filename = None
            if file_data:
                data = file_data.split(',')[1]
                file_ext = file_data.split(',')[0].split(';')[0].split('/')[1]
                filename = f"{str(uuid.uuid4())}.{file_ext}"
                file_path = os.path.join(UPLOAD_DIRECTORY, filename)
                with open(file_path, "wb") as f:
                    f.write(base64.b64decode(data))
            message_doc = await Message.create({
                "sender": websocket.userId,
                "recipient": recipient,
                "text": text,
                "file": filename
            })
            message = {
                "text": text,
                "sender": websocket.userId,
                "recipient": recipient,
                "file": filename,
                "_id": str(message_doc.id)
            }
            for client in connected_clients:
                if client["userId"] == recipient:
                    await client["websocket"].send(json.dumps(message))
        except Exception as e:
            print(f"Error: {e}")

    # Remove the disconnected client from the list of connected clients
    connected_clients.remove({"websocket": websocket, "userId": websocket.userId, "username": websocket.username})
    # Notify all connected clients about the new list of online people
    await notify_about_online_people()

connected_clients = []
