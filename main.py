#https://viblo.asia/p/huong-dan-co-ban-framework-fastapi-tu-a-z-phan-1-V3m5W0oyKO7
#https://viblo.asia/p/huong-dan-co-ban-framework-fastapi-tu-a-z-phan-2-E375zQq6lGW
#https://fastapi.tiangolo.com/advanced/extending-openapi/
#https://fastapi.tiangolo.com/tutorial/security/first-steps/
#cd api
#uvicorn main:app --reload  --host 0.0.0.0 --port 8000
#uvicorn main:app --host 0.0.0.0 --port 8000
#http://127.0.0.1:8000/docs
#http://127.0.0.1:8000/redoc

from typing import Optional  
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, status, Depends, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from pydantic import BaseModel
from fastapi.openapi.utils import get_openapi

from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.staticfiles import StaticFiles

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "scs1": {
        "username": "scs1",
        "full_name": "Admin Account",
        "email": "duy.pham@solutions.io",
        "hashed_password": "fakehashedsecret", #secret
        "disabled": False,
    },
    "scs2": {
        "username": "scs2",
        "full_name": "Member Account",
        "email": "huy.pham@solutions.io",
        "hashed_password": "fakehashedsecret2", #secret2
        "disabled": True,
    },
}
fake_items = {
    "1": {
        "item_id" : 1,
        "item_name": "ACB",
        "weight": 10,
        "disabled": False,
    },
    "2": {
        "item_id" : 2,
        "item_name": "XYZ",
        "weight": 20,
        "disabled": False,
    },
}
fake_data_face = {
    "1": {
        "faceid" : "ub4u3hj4b3h", 
        "success_code": 100,
        "disabled": False,
    },
    "2": {
        "faceid" : "ub4u3hj4b3h", 
        "accuracy": "98",
        "success_code": 101,
        "disabled": False,
    },
}
#app = FastAPI(docs_url=None, redoc_url=None)
app = FastAPI(title="Solutions")

def fake_hash_password(password: str):
    return "fakehashed" + password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#Customize API layout
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger ",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


@app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc",
        redoc_js_url="/static/redoc.standalone.js",
    )
 

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Face Recognition API",
        version="1.0.0",
        description="This is a very usefull API from SOLUTIONS",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://solutions.io/_Logo_original_icon.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi 
 
#End Customize API layout


#Authorize 
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(fake_users_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#End Authorize 
#Define
class Item(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    tax: Optional[float] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#End Define

#API 
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    #access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    #access_token = create_access_token(
    #    data={"sub": user.username}, expires_delta=access_token_expires
    #)
    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/items/{item_id}")
async def read_item(item_id: int, user: str = Depends(oauth2_scheme)):
        #item_id = fake_items.get(item_id)
        if item_id==1: 
            return {"item1":fake_items["1"]}
        elif item_id==2: 
            return {"item2":fake_items["2"]}
        else:
            return {"Code": "Invalid"}
 
@app.post("/items/")
async def create_item(item: Item, user: str = Depends(oauth2_scheme)): 
    #save to db
    return item 

@app.post("/video/")
async def send_video(video_path: str, user: str = Depends(oauth2_scheme)): 
    #save to db
    if video_path=="1": 
        return {"registed":fake_data_face["1"]}
    elif video_path=="2": 
        return {"check_in":fake_data_face["2"]}
    else:
        return {"Code": "Invalid"}
@app.post("/image/")
async def send_image(image_base64: str, user: str = Depends(oauth2_scheme)): 
    #save to db
    if image_base64=="1": 
        return {"registed":fake_data_face["1"]}
    elif image_base64=="2": 
        return {"check_in":fake_data_face["2"]}
    else:
        return {"Code": "Invalid"}
