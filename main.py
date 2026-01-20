from typing import Annotated
from fastapi import FastAPI, Depends , HTTPException, Response, Cookie 
from sqlalchemy.orm import Session
#from passlib.context import CryptContext
import hashlib
from database import engine, Base, get_db
import models
import os 
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from dotenv import load_dotenv

SECRET_KEY = "9876543210abcdef1234567890abcdef" # You can make this any long string
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def create_refresh_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto",bcrypt__truncate_error=False)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Server is running!"}

@app.post("/signup")
def signup(
    email: str,
    password: str, 
    company_name: str, 
    name: str, 
    address: str, 
    db: Session = Depends(get_db)
):
    db_user = db.query(models.User).filter(models.User.email == email).first()
    if db_user:
        raise HTTPException(status_code=400, detail=" Email already registered")
    hashed_password_string = hashlib.sha256(password.encode()).hexdigest()
    new_user = models.User(
        email=email, 
        hashed_password=hashed_password_string, 
        company_name=company_name, 
        name=name, 
        address=address
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message":"User created successfully", "user_id": new_user.id}

@app.post("/api/auth/signin")
def signin(response: Response,email: str, password: str, db: Session = Depends(get_db)):
    clean_email = email.strip() 
    user = db.query(models.User).filter(models.User.email ==clean_email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid Email or Password")
    
    incoming_hash = hashlib.sha256(password.encode()).hexdigest()
    if incoming_hash != user.hashed_password:
        raise HTTPException(status_code = 401, detail="Invalid Email or Password")
    
    #expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    #token_payload= {
       # "user_id" :user.id,
       # "email": user.email,
       # "type": "access",
       # "exp" : expire  }
    #encoded_jwt = jwt.encode(token_payload, SECRET_KEY, algorithm= ALGORITHM)

    #refresh_token = datetime.now(timezone.utc) +timedelta (days =1)
    #refresh_payload= {
     #   "user_id": user.id,
      #  "email": user.email,
       # "type" : "refresh",
        #"exp": refresh_token
   # }  
   
 #encoded_refresh_jwt = jwt.encode(refresh_payload,SECRET_KEY,algorithm= ALGORITHM)
    access_expire = datetime.now(timezone.utc)+ timedelta(minutes =30)
    refresh_expire = datetime.now(timezone.utc) +timedelta(days= 1)
    
   # access_token = create_access_token(data={"user_id": user.id})
   # refresh_token= create_refresh_token(data={"user_id": user.id})
    access_token = jwt.encode({"user_id": user.id,"type":"access","exp":access_expire},SECRET_KEY, algorithm=ALGORITHM)
    refresh_token = jwt.encode({"user_id": user.id,"type":"refresh","exp":refresh_expire},SECRET_KEY,algorithm=ALGORITHM)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly= True,
        max_age= 86400,
        expires=86400,
        samesite="lax",
        secure= False
    )
    
    return{
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "company_name": user.company_name
        }

    }
@app.post("/api/auth/refresh")
def refresh_token_endpoint(refresh_token :Annotated[ str | None,Cookie()]=None, db: Session = Depends(get_db)):
    user = db.query(models.User).first()
    
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh Cookie missing")
    
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms= [ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("user_id")
        #if not user_id:
            #raise HTTPException(status_code=401, detail="User not found")
        user=db.query(models.User).filter(models.User.id == user_id).first()
        access_expire = datetime.now(timezone.utc)+ timedelta(minutes=30)
        new_access_token = jwt.encode(
        {
            "user_id" : user.id,
             "email": user.email,
             "type": "access",
             "exp": access_expire
            },
             SECRET_KEY,
             algorithm= ALGORITHM
        )
        return {
            "access_token": new_access_token,
            "token_type": "bearer"

        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")
@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"message":"Logged out successfully"}
        
    