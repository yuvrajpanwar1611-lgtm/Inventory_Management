# import os
# from typing import List, Optional
# from datetime import datetime, timedelta, timezone
# from decimal import Decimal
# import logging
# import secrets
# import textwrap
# from io import BytesIO

# from fastapi import FastAPI, HTTPException, Depends, status, Body
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import FileResponse

# from pydantic import BaseModel
# from jose import jwt, JWTError
# from passlib.context import CryptContext

# from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
# from tortoise.contrib.fastapi import register_tortoise

# from reportlab.pdfgen import canvas
# from reportlab.lib.pagesizes import A4
# from reportlab.lib import colors
# import qrcode

# # Load environment variables
# from dotenv import load_dotenv
# load_dotenv()

# # ---------------------- LOGGING ----------------------
# logger = logging.getLogger("inventory")
# logging.basicConfig(level=logging.INFO)

# # ---------------------- IMPORT MODELS ----------------------
# from models import (
#     User, User_Pydantic, UserIn_Pydantic,
#     Supplier, supplier_pydantic, supplier_pydanticIn,
#     Products, product_pydantic, product_pydanticIn,
#     StockMovement
# )

# # ========================================================
# #                 APP + CORS CONFIG
# # ========================================================

# app = FastAPI(title="Inventory Management API")

# origins = [
#     "*",
#     "http://localhost:3000",
#     "http://localhost:5173",
#     "https://inventory-management-frontend-hqhs.onrender.com",
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# @app.get("/")
# def home():
#     return {"msg": "API Running"}

# @app.get("/health")
# def health():
#     return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

# # ========================================================
# #                EMAIL CONFIGURATION
# # ========================================================

# EMAIL = os.getenv("EMAIL_USER") or os.getenv("EMAIL")
# PASS = os.getenv("EMAIL_PASS") or os.getenv("PASS")

# MAIL_CONF = None
# if EMAIL and PASS:
#     MAIL_CONF = ConnectionConfig(
#         MAIL_USERNAME=EMAIL,
#         MAIL_PASSWORD=PASS,
#         MAIL_FROM=EMAIL,
#         MAIL_PORT=465,
#         MAIL_SERVER="smtp.gmail.com",
#         MAIL_SSL_TLS=True,
#         MAIL_STARTTLS=False,
#         USE_CREDENTIALS=True,
#         VALIDATE_CERTS=True,
#     )
# else:
#     logger.warning("⚠️ EMAIL NOT CONFIGURED — Email OTP + Invoice email disabled")

# # ========================================================
# #                AUTH / JWT CONFIG
# # ========================================================

# SECRET_KEY = os.getenv("SECRET_KEY")
# if not SECRET_KEY:
#     SECRET_KEY = secrets.token_urlsafe(32)
#     logger.warning("⚠️ SECRET_KEY not set — using temporary key (NOT SAFE FOR PRODUCTION!)")

# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days login

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


# def verify_password(raw, hashed):
#     return pwd_context.verify(raw, hashed)

# def hash_password(pwd):
#     return pwd_context.hash(pwd)

# def create_access_token(data: dict):
#     expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     data.update({"exp": expire})
#     return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user_id = payload.get("sub")
#         if not user_id:
#             raise HTTPException(401, "Invalid token")

#         user = await User.filter(id=int(user_id)).first()
#         if not user:
#             raise HTTPException(401, "User not found")
#         return user
#     except JWTError:
#         raise HTTPException(401, "Invalid or expired token")

# # ========================================================
# #                USER SIGNUP / LOGIN
# # ========================================================

# class SignupSchema(BaseModel):
#     username: str
#     email: str
#     phone: str
#     password: str
#     full_name: Optional[str] = None

# email_verified_set = set()
# verified_numbers = set()

# @app.post("/signup")
# async def signup(data: SignupSchema):
#     """Signup requires verified email + verified phone"""
#     if data.email.strip().lower() not in email_verified_set:
#         raise HTTPException(400, "Email not verified")

#     if data.phone not in verified_numbers:
#         raise HTTPException(400, "Phone not verified")

#     if await User.filter(username=data.username).exists():
#         raise HTTPException(400, "Username already exists")

#     hashed_pw = hash_password(data.password)

#     user = await User.create(
#         username=data.username.strip(),
#         email=data.email.strip().lower(),
#         phone=data.phone,
#         full_name=data.full_name,
#         hashed_password=hashed_pw
#     )

#     email_verified_set.discard(data.email.strip().lower())
#     verified_numbers.discard(data.phone)

#     return {"status": "ok", "user": await User_Pydantic.from_tortoise_orm(user)}

# @app.post("/token")
# async def login(form: OAuth2PasswordRequestForm = Depends()):
#     user = await User.filter(username=form.username).first()
#     if not user or not verify_password(form.password, user.hashed_password):
#         raise HTTPException(401, "Incorrect username or password")

#     token = create_access_token({"sub": str(user.id)})
#     return {
#         "access_token": token,
#         "token_type": "bearer",
#         "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES
#     }

# @app.get("/users/me")
# async def me(user: User = Depends(get_current_user)):
#     return {
#         "id": user.id,
#         "username": user.username,
#         "email": user.email,
#         "phone": user.phone,
#         "full_name": user.full_name
#     }

# # ========================================================
# #                EMAIL OTP SYSTEM
# # ========================================================

# email_otp_store = {}
# email_otp_rate_limit = {}
# EMAIL_OTP_TTL_MINUTES = 5

# class EmailRequest(BaseModel):
#     email: str

# class EmailVerifyRequest(BaseModel):
#     email: str
#     otp: int

# def _generate_otp():
#     return 100000 + secrets.randbelow(900000)

# @app.post("/send-email-otp")
# async def send_email_otp(data: EmailRequest):
#     if not MAIL_CONF:
#         raise HTTPException(500, "Email server not configured")

#     email = data.email.strip().lower()
#     now = datetime.now(timezone.utc)

#     if email in email_otp_rate_limit and (now - email_otp_rate_limit[email]).seconds < 60:
#         raise HTTPException(429, "Wait before requesting again")

#     otp = _generate_otp()
#     email_otp_store[email] = {"otp": otp, "expires": now + timedelta(minutes=EMAIL_OTP_TTL_MINUTES)}
#     email_otp_rate_limit[email] = now

#     fm = FastMail(MAIL_CONF)
#     html = f"""<h2>Your OTP: {otp}</h2>"""

#     message = MessageSchema(
#         subject="Email OTP Verification",
#         recipients=[email],
#         body=html,
#         subtype=MessageType.html,
#     )

#     await fm.send_message(message)
#     return {"status": "ok", "expires_in": EMAIL_OTP_TTL_MINUTES}

# @app.post("/verify-email-otp")
# async def verify_email_otp(data: EmailVerifyRequest):
#     email = data.email.strip().lower()

#     entry = email_otp_store.get(email)
#     if not entry:
#         raise HTTPException(400, "OTP not found")

#     if entry["expires"] < datetime.now(timezone.utc):
#         email_otp_store.pop(email, None)
#         raise HTTPException(400, "OTP expired")

#     if entry["otp"] != data.otp:
#         raise HTTPException(400, "Invalid OTP")

#     email_otp_store.pop(email, None)
#     email_verified_set.add(email)

#     return {"verified": True}

# # ========================================================
# #                PHONE OTP SYSTEM
# # ========================================================

# mobile_otp_store = {}
# otp_rate_limit = {}
# OTP_TTL_MINUTES = 5

# class OTPRequest(BaseModel):
#     mobile: str

# class OTPVerifyRequest(BaseModel):
#     mobile: str
#     otp: int

# @app.post("/send-otp")
# def send_otp(data: OTPRequest):
#     now = datetime.now(timezone.utc)
#     mobile = data.mobile.strip()

#     if mobile in otp_rate_limit and (now - otp_rate_limit[mobile]).seconds < 60:
#         raise HTTPException(429, "Wait before requesting OTP")

#     otp = _generate_otp()
#     mobile_otp_store[mobile] = {"otp": otp, "expires": now + timedelta(minutes=OTP_TTL_MINUTES)}
#     otp_rate_limit[mobile] = now

#     logger.info(f"OTP for {mobile}: {otp}")
#     return {"message": "OTP sent"}

# @app.post("/verify-otp")
# def verify_otp(data: OTPVerifyRequest):
#     entry = mobile_otp_store.get(data.mobile)
#     if not entry:
#         raise HTTPException(400, "OTP not found")

#     if entry["expires"] < datetime.now(timezone.utc):
#         raise HTTPException(400, "OTP expired")

#     if entry["otp"] != data.otp:
#         raise HTTPException(400, "Incorrect OTP")

#     verified_numbers.add(data.mobile)
#     mobile_otp_store.pop(data.mobile, None)

#     return {"verified": True}

# # ========================================================
# #                PRODUCT CRUD + MOVEMENTS
# # ========================================================

# @app.post("/product/{supplier_id}")
# async def add_product(supplier_id: int, data: product_pydanticIn, user: User = Depends(get_current_user)):

#     supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()
#     if not supplier:
#         raise HTTPException(404, "Supplier not found")

#     obj = await Products.create(
#         **data.dict(),
#         supplied_by=supplier,
#         user_id=user.id
#     )
#     return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(obj)}

# @app.get("/product")
# async def get_products(user: User = Depends(get_current_user)):
#     items = await Products.filter(user_id=user.id).prefetch_related("supplied_by")
#     out = []

#     for p in items:
#         d = (await product_pydantic.from_tortoise_orm(p)).dict()
#         d["supplied_by_id"] = p.supplied_by_id
#         out.append(d)

#     return {"status": "ok", "data": out}

# @app.put("/product/{id}")
# async def update_product(id: int, data: product_pydanticIn, user: User = Depends(get_current_user)):
#     p = await Products.filter(id=id, user_id=user.id).first()
#     if not p:
#         raise HTTPException(404, "Product not found")

#     for k, v in data.dict().items():
#         setattr(p, k, v)

#     p.revenue = p.quantity_sold * p.unit_price
#     p.net_profit = p.quantity_sold * p.profit_per_piece
#     await p.save()

#     return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(p)}

# @app.delete("/product/{id}")
# async def delete_product(id: int, user: User = Depends(get_current_user)):
#     deleted = await Products.filter(id=id, user_id=user.id).delete()
#     if not deleted:
#         raise HTTPException(404, "Product not found")
#     return {"status": "ok"}

# # ========================================================
# #             PURCHASE PRODUCT
# # ========================================================

# class PurchaseData(BaseModel):
#     supplier_id: int
#     quantity: int
#     buy_price: float

# @app.post("/product/purchase/{product_id}")
# async def purchase_product(product_id: int, data: PurchaseData, user: User = Depends(get_current_user)):

#     product = await Products.filter(id=product_id, user_id=user.id).first()
#     if not product:
#         raise HTTPException(404, "Product not found")

#     supplier = await Supplier.filter(id=data.supplier_id, user_id=user.id).first()
#     if not supplier:
#         raise HTTPException(404, "Supplier not found")

#     if data.quantity <= 0:
#         raise HTTPException(400, "Quantity must be > 0")
#     if data.buy_price <= 0:
#         raise HTTPException(400, "Price must be > 0")

#     product.quantity_in_stock += data.quantity
#     product.last_purchase_price = Decimal(str(data.buy_price))
#     product.supplied_by_id = data.supplier_id
#     await product.save()

#     await StockMovement.create(
#         product_id=product_id,
#         movement_type="purchase",
#         quantity=data.quantity,
#         price_per_unit=Decimal(str(data.buy_price)),
#         total_amount=Decimal(str(data.buy_price)) * data.quantity,
#         supplier_id=data.supplier_id,
#         user_id=user.id,
#     )

#     return {"status": "ok"}

# # ========================================================
# #               SELL PRODUCT (INVOICE)
# # ========================================================

# class SellItem(BaseModel):
#     product_id: int
#     quantity: int
#     sell_price: float

# class SellMultiData(BaseModel):
#     items: List[SellItem]
#     customer_name: str
#     customer_phone: str
#     customer_email: str

# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# INVOICE_DIR = os.path.join(BASE_DIR, "invoices")
# os.makedirs(INVOICE_DIR, exist_ok=True)

# def generate_invoice_pdf(invoice_no, items, total, customer, timestamp):
#     filepath = os.path.join(INVOICE_DIR, f"{invoice_no}.pdf")
#     c = canvas.Canvas(filepath, pagesize=A4)

#     PAGE_WIDTH, PAGE_HEIGHT = A4
#     x = 30
#     y = PAGE_HEIGHT - 50

#     c.setFont("Helvetica-Bold", 20)
#     c.drawString(x, y, "MOBILE WORLD LTD")
#     y -= 40

#     c.setFont("Helvetica", 12)
#     c.drawString(x, y, f"Invoice No: {invoice_no}")
#     y -= 20
#     c.drawString(x, y, f"Date: {timestamp}")
#     y -= 30

#     c.setFont("Helvetica-Bold", 12)
#     c.drawString(x, y, "Customer:")
#     y -= 20

#     c.setFont("Helvetica", 11)
#     c.drawString(x, y, customer.customer_name)
#     y -= 20
#     c.drawString(x, y, customer.customer_email)
#     y -= 20
#     c.drawString(x, y, customer.customer_phone)
#     y -= 30

#     c.setFont("Helvetica-Bold", 12)
#     c.drawString(x, y, "Items")
#     y -= 20

#     c.setFont("Helvetica", 10)
#     for item in items:
#         c.drawString(x, y, f"{item['name']}  x{item['qty']}  —  ₹{item['total']}")
#         y -= 20

#     c.setFont("Helvetica-Bold", 12)
#     y -= 10
#     c.drawString(x, y, f"Grand Total: ₹{total}")
#     y -= 30

#     c.save()
#     return filepath

# @app.post("/product/sell")
# async def sell_products(data: SellMultiData, user: User = Depends(get_current_user)):

#     invoice_no = f"INV-{int(datetime.now().timestamp())}"
#     items_output = []
#     grand_total = Decimal("0")

#     for item in data.items:

#         product = await Products.filter(id=item.product_id, user_id=user.id).first()
#         if not product:
#             raise HTTPException(404, f"Product not found")

#         if product.quantity_in_stock < item.quantity:
#             raise HTTPException(400, f"Not enough stock for {product.name}")

#         qty = item.quantity
#         price = Decimal(str(item.sell_price))
#         total = qty * price

#         items_output.append({
#             "name": product.name,
#             "qty": qty,
#             "price": float(price),
#             "total": float(total),
#         })

#         product.quantity_in_stock -= qty
#         product.quantity_sold += qty
#         product.revenue += total
#         product.net_profit += qty * product.profit_per_piece
#         await product.save()

#         await StockMovement.create(
#             product_id=product.id,
#             movement_type="sale",
#             quantity=qty,
#             price_per_unit=price,
#             total_amount=total,
#             user_id=user.id,
#             customer_name=data.customer_name,
#             customer_phone=data.customer_phone,
#             customer_email=data.customer_email,
#             invoice_number=invoice_no
#         )

#         grand_total += total

#     timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")
#     pdf_path = generate_invoice_pdf(invoice_no, items_output, grand_total, data, timestamp)

#     return {"status": "ok", "invoice_pdf": f"/download_invoice/{invoice_no}"}

# @app.get("/download_invoice/{invoice_no}")
# async def download_inv(invoice_no: str, user: User = Depends(get_current_user)):
#     movement = await StockMovement.filter(invoice_number=invoice_no, user_id=user.id).first()
#     if not movement:
#         raise HTTPException(404, "Invoice not found")

#     path = os.path.join(INVOICE_DIR, f"{invoice_no}.pdf")
#     if not os.path.exists(path):
#         raise HTTPException(404, "File missing")

#     return FileResponse(path, media_type="application/pdf", filename=f"{invoice_no}.pdf")

# # ========================================================
# #                  SUPPLIER CRUD
# # ========================================================

# @app.post("/supplier")
# async def add_supplier(data: supplier_pydanticIn, user: User = Depends(get_current_user)):
#     obj = await Supplier.create(**data.dict(), user_id=user.id)
#     return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(obj)}

# @app.get("/supplier")
# async def get_suppliers(user: User = Depends(get_current_user)):
#     qs = Supplier.filter(user_id=user.id)
#     data = await supplier_pydantic.from_queryset(qs)
#     return {"status": "ok", "data": data}

# @app.get("/supplier/{id}")
# async def get_supplier(id: int, user: User = Depends(get_current_user)):
#     s = await Supplier.filter(id=id, user_id=user.id).first()
#     if not s:
#         raise HTTPException(404, "Supplier not found")
#     return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(s)}

# @app.put("/supplier/{id}")
# async def update_supplier(id: int, data: supplier_pydanticIn, user: User = Depends(get_current_user)):
#     s = await Supplier.filter(id=id, user_id=user.id).first()
#     if not s:
#         raise HTTPException(404, "Supplier not found")

#     for k, v in data.dict().items():
#         setattr(s, k, v)

#     await s.save()
#     return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(s)}

# @app.delete("/supplier/{id}")
# async def delete_supplier(id: int, user: User = Depends(get_current_user)):
#     deleted = await Supplier.filter(id=id, user_id=user.id).delete()
#     if not deleted:
#         raise HTTPException(404, "Supplier not found")
#     return {"status": "ok"}

# # ========================================================
# #               STOCK MOVEMENTS
# # ========================================================

# @app.get("/movements")
# async def all_movements(user: User = Depends(get_current_user)):
#     items = await StockMovement.filter(user_id=user.id).order_by("-timestamp")
#     out = []

#     for m in items:
#         product = await m.product
#         out.append({
#             "id": m.id,
#             "product_id": m.product_id,
#             "product_name": product.name if product else None,
#             "movement_type": m.movement_type,
#             "quantity": m.quantity,
#             "price_per_unit": str(m.price_per_unit),
#             "total_amount": str(m.total_amount),
#             "supplier_id": m.supplier_id,
#             "customer_name": m.customer_name,
#             "customer_phone": m.customer_phone,
#             "customer_email": m.customer_email,
#             "timestamp": str(m.timestamp),
#             "invoice_number": m.invoice_number,
#         })

#     return {"status": "ok", "data": out}

# # ========================================================
# #              DATABASE REGISTRATION
# # ========================================================

# DB_URL = os.getenv("DB_URL")
# if not DB_URL:
#     raise Exception("❌ DB_URL missing in environment variables!")

# register_tortoise(
#     app,
#     db_url=DB_URL,
#     modules={"models": ["models"]},
#     generate_schemas=False,
#     add_exception_handlers=True,
# )

# logger.info("✅ Database connected successfully")

# app.py
import os
import secrets
import logging
from typing import List, Optional
from datetime import datetime, timedelta
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

# ========================================================
#                 APP + CORS CONFIG
# ========================================================

app = FastAPI(title="Inventory Management API")

origins = [
    "*",
    "http://localhost:3000",
    "http://localhost:5173",
    "https://inventory-management-frontend-hqhs.onrender.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"msg": "API Running"}

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
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def verify_password(raw, hashed):
    return pwd_context.verify(raw, hashed)

def hash_password(raw):
    return pwd_context.hash(raw)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user = await User.filter(id=int(user_id)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

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
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # IMPORTANT: sub = user.id (string)
    token = create_access_token({"sub": str(user.id)})

    return {
        "access_token": token,
        "token_type": "bearer"
    }

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
# INVOICE PDF
# ======================================================
def generate_invoice_pdf_multi(invoice_no, items, grand_total, data, timestamp):
    os.makedirs("invoices", exist_ok=True)
    path = f"invoices/{invoice_no}.pdf"

    c = canvas.Canvas(path, pagesize=A4)
    w, h = A4
    y = h - 40

    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(w / 2, y, "MOBILE WORLD LTD")
    y -= 30

    c.setFont("Helvetica", 11)
    c.drawString(40, y, f"Invoice No: {invoice_no}")
    c.drawRightString(w - 40, y, f"Date: {timestamp}")
    y -= 25

    c.drawString(40, y, f"Customer: {data.customer_name}")
    y -= 15
    c.drawString(40, y, f"Email: {data.customer_email}")
    y -= 30

    c.setFillColor(colors.lightgrey)
    c.rect(40, y, w - 80, 20, fill=1)
    c.setFillColor(colors.black)

    c.drawString(50, y + 5, "Product")
    c.drawString(250, y + 5, "Qty")
    c.drawString(300, y + 5, "Price")
    c.drawString(380, y + 5, "Total")
    y -= 25

    for it in items:
        c.drawString(50, y, it["name"])
        c.drawString(250, y, str(it["qty"]))
        c.drawString(300, y, f"{it['price']}")
        c.drawString(380, y, f"{it['total']}")
        y -= 20

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(w - 40, y, f"Grand Total: {grand_total}")

    c.save()
    return path

# ======================================================
# SCHEMAS
# ======================================================
class PurchaseData(BaseModel):
    supplier_id: int
    quantity: int
    buy_price: float

class SellItem(BaseModel):
    product_id: int
    quantity: int
    sell_price: float

class SellMultiData(BaseModel):
    items: List[SellItem]
    customer_name: str
    customer_phone: str
    customer_email: str

# ======================================================
# SUPPLIER CRUD
# ======================================================
@app.post("/supplier")
async def add_supplier(data: supplier_pydanticIn, user: User = Depends(get_current_user)):
    obj = await Supplier.create(**data.dict(), user_id=user.id)
    return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(obj)}

@app.get("/supplier")
async def get_suppliers(user: User = Depends(get_current_user)):
    return {
        "status": "ok",
        "data": await supplier_pydantic.from_queryset(
            Supplier.filter(user_id=user.id)
        )
    }

@app.put("/supplier/{supplier_id}")
async def update_supplier(
    supplier_id: int,
    data: dict = Body(...),
    user: User = Depends(get_current_user)
):
    supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()
    if not supplier:
        raise HTTPException(404, "Supplier not found")

    for k, v in data.items():
        if hasattr(supplier, k):
            setattr(supplier, k, v)

    await supplier.save()
    return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(supplier)}

@app.delete("/supplier/{supplier_id}")
async def delete_supplier(supplier_id: int, user: User = Depends(get_current_user)):
    await Supplier.filter(id=supplier_id, user_id=user.id).delete()
    return {"status": "ok"}

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
        d = (await product_pydantic.from_tortoise_orm(p)).dict()
        d["supplied_by_id"] = p.supplied_by_id
        out.append(d)
    return {"status": "ok", "data": out}

# ======================================================
# PURCHASE
# ======================================================
@app.post("/product/purchase/{product_id}")
async def purchase_product(
    product_id: int,
    data: PurchaseData,
    user: User = Depends(get_current_user)
):
    product = await Products.filter(id=product_id, user_id=user.id).first()
    supplier = await Supplier.filter(id=data.supplier_id, user_id=user.id).first()

    if not product or not supplier:
        raise HTTPException(404, "Invalid product or supplier")

    product.quantity_in_stock += data.quantity
    product.last_purchase_price = Decimal(str(data.buy_price))
    await product.save()

    await StockMovement.create(
        product_id=product.id,
        movement_type="purchase",
        quantity=data.quantity,
        price_per_unit=Decimal(str(data.buy_price)),
        total_amount=Decimal(str(data.buy_price)) * data.quantity,
        supplier_id=supplier.id,
        user_id=user.id
    )

    return {"status": "ok"}

# ======================================================
# SELL MULTI
# ======================================================
@app.post("/product/sell-multi")
async def sell_multi(data: SellMultiData, user: User = Depends(get_current_user)):
    invoice = f"INV-{int(datetime.now().timestamp())}"
    timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    items_out = []
    grand_total = Decimal("0")

    async with in_transaction():
        for item in data.items:
            product = await Products.filter(
                id=item.product_id,
                user_id=user.id
            ).first()

            if not product:
                raise HTTPException(404, f"Product {item.product_id} not found")

            if product.quantity_in_stock < item.quantity:
                raise HTTPException(
                    400,
                    f"Insufficient stock for {product.name}"
                )

            price = Decimal(str(item.sell_price))
            qty = item.quantity
            total = price * qty

            # Update product
            product.quantity_in_stock -= qty
            product.quantity_sold += qty
            product.revenue += total
            product.net_profit += qty * product.profit_per_piece
            await product.save()

            # Stock movement
            await StockMovement.create(
                product_id=product.id,
                movement_type="sale",
                quantity=qty,
                price_per_unit=price,
                total_amount=total,
                customer_name=data.customer_name,
                customer_phone=data.customer_phone,
                customer_email=data.customer_email,
                invoice_number=invoice,
                user_id=user.id
            )

            items_out.append({
                "name": product.name,
                "qty": qty,
                "price": float(price),
                "total": float(total)
            })

            grand_total += total

    # Generate invoice AFTER DB success
    generate_invoice_pdf_multi(
        invoice,
        items_out,
        grand_total,
        data,
        timestamp
    )

    return {
        "status": "ok",
        "invoice_pdf": f"/download_invoice/{invoice}"
    }
# ======================================================
# DOWNLOAD INVOICE
# ======================================================
@app.get("/download_invoice/{invoice}")
async def download_invoice(invoice: str, user: User = Depends(get_current_user)):
    path = f"invoices/{invoice}.pdf"
    if not os.path.exists(path):
        raise HTTPException(404, "Invoice not found")
    return FileResponse(path, filename=f"{invoice}.pdf")

# ======================================================
# MOVEMENTS
# ======================================================
@app.get("/movements")
async def movements(user: User = Depends(get_current_user)):
    out = []
    for m in await StockMovement.filter(user_id=user.id).order_by("-timestamp"):
        p = await m.product
        out.append({
            "product": p.name if p else None,
            "type": m.movement_type,
            "qty": m.quantity,
            "amount": str(m.total_amount),
            "time": m.timestamp
        })
    return {"data": out}

# ======================================================
# DATABASE
# ======================================================
DB_URL = os.getenv("DB_URL")
if not DB_URL:
    raise Exception("❌ DB_URL missing in environment variables!")

register_tortoise(
    app,
    db_url=DB_URL,
    modules={"models": ["models"]},
    generate_schemas=False,
    add_exception_handlers=True,
)

logger.info("✅ Database connected successfully")


