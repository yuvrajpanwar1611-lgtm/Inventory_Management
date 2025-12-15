# from tortoise import fields, models
# from tortoise.contrib.pydantic import pydantic_model_creator


# # ============================================================
# #                          USER MODEL
# # ============================================================

# class User(models.Model):
#     id = fields.IntField(pk=True)

#     username = fields.CharField(max_length=40, unique=True, index=True)
#     email = fields.CharField(max_length=120, unique=True, index=True)
#     phone = fields.CharField(max_length=20, unique=True)

#     full_name = fields.CharField(max_length=120, null=True)
#     hashed_password = fields.CharField(max_length=255)

#     is_active = fields.BooleanField(default=True)
#     created_at = fields.DatetimeField(auto_now_add=True)

#     class Meta:
#         table = "users"


# # ============================================================
# #                       SUPPLIER MODEL
# # ============================================================

# class Supplier(models.Model):
#     id = fields.IntField(pk=True)

#     name = fields.CharField(max_length=60)
#     company = fields.CharField(max_length=80)

#     # ❗️ IMPORTANT FIX:
#     # Email & phone should NOT be globally unique.
#     # Multiple users can have suppliers with same email/phone.
#     email = fields.CharField(max_length=120)
#     phone = fields.CharField(max_length=20)

#     user = fields.ForeignKeyField("models.User", related_name="suppliers")

#     class Meta:
#         table = "supplier"
#         unique_together = (("user_id", "email"), ("user_id", "phone"))


# # ============================================================
# #                       PRODUCT MODEL
# # ============================================================

# class Products(models.Model):
#     id = fields.IntField(pk=True)
#     name = fields.CharField(max_length=100)

#     quantity_in_stock = fields.IntField(default=0)
#     quantity_sold = fields.IntField(default=0)

#     unit_price = fields.DecimalField(max_digits=12, decimal_places=2, default=0.00)
#     revenue = fields.DecimalField(max_digits=20, decimal_places=2, default=0.00)

#     profit_per_piece = fields.DecimalField(max_digits=10, decimal_places=2, default=0.00)
#     net_profit = fields.DecimalField(max_digits=20, decimal_places=2, default=0.00)

#     last_purchase_price = fields.DecimalField(max_digits=12, decimal_places=2, default=0.00)

#     # Supplier
#     supplied_by = fields.ForeignKeyField("models.Supplier", related_name="goods_supplied", null=True)

#     # User owner (multi-user system)
#     user = fields.ForeignKeyField("models.User", related_name="products")

#     class Meta:
#         table = "products"


# # ============================================================
# #                  STOCK MOVEMENT MODEL
# # ============================================================

# class StockMovement(models.Model):
#     id = fields.IntField(pk=True)

#     product = fields.ForeignKeyField("models.Products", related_name="movements")

#     movement_type = fields.CharField(max_length=20)  # purchase / sale
#     quantity = fields.IntField()

#     price_per_unit = fields.DecimalField(max_digits=12, decimal_places=2)
#     total_amount = fields.DecimalField(max_digits=18, decimal_places=2)

#     supplier = fields.ForeignKeyField("models.Supplier", related_name="movements", null=True)

#     customer_name = fields.CharField(max_length=200, null=True)
#     customer_phone = fields.CharField(max_length=50, null=True)
#     customer_email = fields.CharField(max_length=200, null=True)

#     invoice_number = fields.CharField(max_length=120, null=True)

#     timestamp = fields.DatetimeField(auto_now_add=True)

#     # Multi-user support
#     user = fields.ForeignKeyField("models.User", related_name="movements")

#     class Meta:
#         table = "stock_movement"


# # ============================================================
# #                 Pydantic Schemas
# # ============================================================

# User_Pydantic = pydantic_model_creator(User, name="UserOut")

# # ❗️ Don't expose hashed password
# UserIn_Pydantic = pydantic_model_creator(
#     User,
#     name="UserIn",
#     exclude=("hashed_password", "is_active", "created_at"),
# )

# product_pydantic = pydantic_model_creator(Products, name="Product")
# product_pydanticIn = pydantic_model_creator(
#     Products,
#     name="ProductIn",
#     exclude_readonly=True
# )

# supplier_pydantic = pydantic_model_creator(Supplier, name="Supplier")
# supplier_pydanticIn = pydantic_model_creator(
#     Supplier,
#     name="SupplierIn",
#     exclude_readonly=True
# )

# stockmovement_pydantic = pydantic_model_creator(StockMovement, name="StockMovement")













# app.py
import os
import secrets
import logging
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
from tortoise.contrib.fastapi import register_tortoise
from tortoise.transactions import in_transaction

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

from dotenv import load_dotenv
load_dotenv()

# ======================================================
# LOGGING
# ======================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("inventory")

# ======================================================
# MODELS
# ======================================================
from models import (
    User, User_Pydantic,
    Supplier, supplier_pydantic, supplier_pydanticIn,
    Products, product_pydantic, product_pydanticIn,
    StockMovement
)

# ======================================================
# APP + CORS
# ======================================================
app = FastAPI(title="Inventory Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://inventory-management-frontend-hqhs.onrender.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "API running"}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

# ======================================================
# EMAIL CONFIG
# ======================================================
EMAIL = os.getenv("EMAIL")
PASS = os.getenv("PASS")

MAIL_CONF = None
if EMAIL and PASS:
    MAIL_CONF = ConnectionConfig(
        MAIL_USERNAME=EMAIL,
        MAIL_PASSWORD=PASS,
        MAIL_FROM=EMAIL,
        MAIL_PORT=465,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_SSL_TLS=True,
        MAIL_STARTTLS=False,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True
    )

# ======================================================
# AUTH / JWT
# ======================================================
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def hash_password(raw: str):
    return pwd_context.hash(raw)

def verify_password(raw: str, hashed: str):
    return pwd_context.verify(raw, hashed)

def create_access_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(401, "Invalid token")

        user = await User.filter(id=int(user_id)).first()
        if not user:
            raise HTTPException(401, "User not found")

        return user
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

# ======================================================
# AUTH ROUTES
# ======================================================
class SignupSchema(BaseModel):
    username: str
    email: str
    phone: str
    password: str
    full_name: Optional[str] = None

@app.post("/signup")
async def signup(data: SignupSchema):
    if await User.filter(username=data.username).exists():
        raise HTTPException(400, "Username already exists")

    user = await User.create(
        username=data.username,
        email=data.email,
        phone=data.phone,
        full_name=data.full_name,
        hashed_password=hash_password(data.password)
    )

    return {"status": "ok", "user": await User_Pydantic.from_tortoise_orm(user)}

@app.post("/token")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = await User.filter(username=form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")

    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "full_name": user.full_name
    }

# ======================================================
# PRODUCT CRUD
# ======================================================
@app.post("/product/{supplier_id}")
async def add_product(
    supplier_id: int,
    data: product_pydanticIn,
    user: User = Depends(get_current_user)
):
    supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()
    if not supplier:
        raise HTTPException(404, "Supplier not found")

    d = data.dict(exclude_unset=True)
    d["revenue"] = d.get("quantity_sold", 0) * d.get("unit_price", 0)
    d["net_profit"] = d.get("profit_per_piece", 0) * d.get("quantity_sold", 0)

    obj = await Products.create(**d, supplied_by=supplier, user_id=user.id)
    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(obj)}

@app.get("/product")
async def get_products(user: User = Depends(get_current_user)):
    products = await Products.filter(user_id=user.id).prefetch_related("supplied_by")

    out = []
    for p in products:
        out.append({
            "id": p.id,
            "name": p.name,
            "quantity_in_stock": p.quantity_in_stock,
            "quantity_sold": p.quantity_sold,
            "unit_price": str(p.unit_price),
            "revenue": str(p.revenue),
            "profit_per_piece": str(p.profit_per_piece),
            "net_profit": str(p.net_profit),
            "last_purchase_price": str(p.last_purchase_price),
            "supplied_by_id": p.supplied_by_id,
        })

    return {"status": "ok", "data": out}

# ======================================================
# DATABASE
# ======================================================
DB_URL = os.getenv("DB_URL")
if not DB_URL:
    raise RuntimeError("❌ DB_URL missing in environment variables")

register_tortoise(
    app,
    db_url=DB_URL,
    modules={"models": ["models"]},
    generate_schemas=False,
    add_exception_handlers=True,
)

logger.info("✅ Inventory API started successfully")
