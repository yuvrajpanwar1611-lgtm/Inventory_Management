# # app.py
# import os
# import secrets
# import logging
# from typing import List, Optional
# from datetime import datetime, timedelta, timezone
# from decimal import Decimal

# from fastapi import FastAPI, HTTPException, Depends, Body
# from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import FileResponse

# from pydantic import BaseModel
# from jose import jwt, JWTError
# from passlib.context import CryptContext

# from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig
# from tortoise.contrib.fastapi import register_tortoise
# from tortoise.transactions import in_transaction

# from reportlab.pdfgen import canvas
# from reportlab.lib.pagesizes import A4
# from reportlab.lib import colors

# from dotenv import load_dotenv
# load_dotenv()

# # ======================================================
# # LOGGING
# # ======================================================
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger("inventory")

# # ======================================================
# # MODELS
# # ======================================================
# from models import (
#     User, User_Pydantic,
#     Supplier, supplier_pydantic, supplier_pydanticIn,
#     Products, product_pydantic, product_pydanticIn,
#     StockMovement
# )

# # ========================================================
# #                 APP + CORS CONFIG
# # ========================================================


# app = FastAPI(title="Inventory Management API")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[
#         "http://localhost:3000",
#         "http://localhost:5173",
#         "https://inventory-management-frontend-hqhs.onrender.com",
#     ],
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

# # ======================================================
# # EMAIL CONFIG
# # ======================================================
# EMAIL = os.getenv("EMAIL") or os.getenv("MAIL_USERNAME")
# PASS = os.getenv("PASS") or os.getenv("MAIL_PASSWORD")

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
#         VALIDATE_CERTS=True
#     )

# # ======================================================
# # AUTH / JWT
# # ======================================================
# SECRET_KEY = os.getenv("SECRET_KEY")
# if not SECRET_KEY:
#     # Stable fallback to avoid invalidating tokens on every restart; override in production.
#     SECRET_KEY = "super_secret_key_change_me"
#     logger.warning("⚠️ SECRET_KEY not set — using insecure fallback (set SECRET_KEY in env!)")
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# def verify_password(raw, hashed):
#     return pwd_context.verify(raw, hashed)

# def hash_password(raw):
#     return pwd_context.hash(raw)

# def create_access_token(data: dict):
#     to_encode = data.copy()
#     expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#     to_encode.update({"exp": expire})
#     return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     if not token:
#         raise HTTPException(status_code=401, detail="Missing token")

#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         user_id = payload.get("sub")

#         if user_id is None:
#             raise HTTPException(status_code=401, detail="Invalid token payload")

#         user = await User.filter(id=int(user_id)).first()
#         if not user:
#             raise HTTPException(status_code=401, detail="User not found")

#         return user

#     except JWTError:
#         raise HTTPException(status_code=401, detail="Invalid or expired token")

# # ======================================================
# # AUTH ROUTES
# # ======================================================
# class SignupSchema(BaseModel):
#     username: str
#     email: str
#     phone: str
#     password: str
#     full_name: Optional[str] = None

# @app.post("/signup")
# async def signup(data: SignupSchema):
#     if await User.filter(username=data.username).exists():
#         raise HTTPException(400, "Username already exists")

#     user = await User.create(
#         username=data.username,
#         email=data.email,
#         phone=data.phone,
#         full_name=data.full_name,
#         hashed_password=hash_password(data.password)
#     )

#     return {"status": "ok", "user": await User_Pydantic.from_tortoise_orm(user)}

# @app.post("/token")
# async def login(form: OAuth2PasswordRequestForm = Depends()):
#     user = await User.filter(username=form.username).first()

#     if not user or not verify_password(form.password, user.hashed_password):
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     # IMPORTANT: sub = user.id (string)
#     token = create_access_token({"sub": str(user.id)})

#     return {
#         "access_token": token,
#         "token_type": "bearer"
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


# # ======================================================
# # OTP (Email + Phone) with TTL + basic rate limiting
# # ======================================================
# EMAIL_OTP_TTL_MINUTES = 5
# OTP_TTL_MINUTES = 5
# OTP_RATE_WINDOW_SECONDS = 60

# email_otp_store = {}       # {email: {"otp": int, "expires": datetime}}
# email_otp_rate_limit = {}  # {email: datetime}

# mobile_otp_store = {}      # {mobile: {"otp": int, "expires": datetime}}
# mobile_otp_rate_limit = {} # {mobile: datetime}


# def _generate_otp():
#     return 100000 + secrets.randbelow(900000)  # 6-digit


# class EmailOtpRequest(BaseModel):
#     email: str


# class EmailOtpVerify(BaseModel):
#     email: str
#     otp: int


# class PhoneOtpRequest(BaseModel):
#     mobile: str


# class PhoneOtpVerify(BaseModel):
#     mobile: str
#     otp: int


# @app.post("/send-email-otp")
# async def send_email_otp(data: EmailOtpRequest):
#     if not MAIL_CONF:
#         raise HTTPException(500, "Email server not configured")

#     email = data.email.strip().lower()

#     now = datetime.now(timezone.utc)
#     last = email_otp_rate_limit.get(email)
#     if last and (now - last).total_seconds() < OTP_RATE_WINDOW_SECONDS:
#         raise HTTPException(429, "Wait before requesting again")

#     otp = _generate_otp()
#     email_otp_store[email] = {"otp": otp, "expires": now + timedelta(minutes=EMAIL_OTP_TTL_MINUTES)}
#     email_otp_rate_limit[email] = now

#     fm = FastMail(MAIL_CONF)
#     html = f"""<h3>Your Email Verification OTP</h3><p><strong>{otp}</strong> (valid for {EMAIL_OTP_TTL_MINUTES} minutes)</p>"""

#     message = MessageSchema(
#         subject="Email OTP Verification",
#         recipients=[email],
#         body=html,
#         subtype=MessageType.html,
#     )

#     await fm.send_message(message)
#     return {"status": "ok", "expires_in": EMAIL_OTP_TTL_MINUTES}


# @app.post("/verify-email-otp")
# async def verify_email_otp(data: EmailOtpVerify):
#     email = data.email.strip().lower()
#     otp = data.otp

#     entry = email_otp_store.get(email)
#     if not entry:
#         raise HTTPException(400, "OTP not found")

#     now = datetime.now(timezone.utc)
#     if entry["expires"] < now:
#         email_otp_store.pop(email, None)
#         raise HTTPException(400, "OTP expired")

#     if entry["otp"] != otp:
#         raise HTTPException(400, "Invalid OTP")

#     email_otp_store.pop(email, None)
#     return {"verified": True}


# @app.post("/send-otp")
# def send_otp(data: PhoneOtpRequest):
#     mobile = data.mobile.strip()

#     now = datetime.now(timezone.utc)
#     last = mobile_otp_rate_limit.get(mobile)
#     if last and (now - last).total_seconds() < OTP_RATE_WINDOW_SECONDS:
#         raise HTTPException(429, "Wait before requesting OTP")

#     otp = _generate_otp()
#     mobile_otp_store[mobile] = {"otp": otp, "expires": now + timedelta(minutes=OTP_TTL_MINUTES)}
#     mobile_otp_rate_limit[mobile] = now

#     logger.info(f"OTP for {mobile}: {otp}")
#     return {"message": "OTP sent", "expires_in": OTP_TTL_MINUTES}


# @app.post("/verify-otp")
# def verify_otp(data: PhoneOtpVerify):
#     mobile = data.mobile.strip()
#     otp = data.otp

#     entry = mobile_otp_store.get(mobile)
#     if not entry:
#         raise HTTPException(400, "OTP not found")

#     now = datetime.now(timezone.utc)
#     if entry["expires"] < now:
#         mobile_otp_store.pop(mobile, None)
#         raise HTTPException(400, "OTP expired")

#     if entry["otp"] != otp:
#         raise HTTPException(400, "Incorrect OTP")

#     mobile_otp_store.pop(mobile, None)
#     return {"verified": True}


# # ======================================================
# # INVOICE PDF
# # ======================================================
# def generate_invoice_pdf_multi(invoice_no, items, grand_total, data, timestamp):
#     os.makedirs("invoices", exist_ok=True)
#     path = f"invoices/{invoice_no}.pdf"

#     c = canvas.Canvas(path, pagesize=A4)
#     w, h = A4
#     y = h - 40

#     c.setFont("Helvetica-Bold", 22)
#     c.drawCentredString(w / 2, y, "MOBILE WORLD LTD")
#     y -= 30

#     c.setFont("Helvetica", 11)
#     c.drawString(40, y, f"Invoice No: {invoice_no}")
#     c.drawRightString(w - 40, y, f"Date: {timestamp}")
#     y -= 25

#     c.drawString(40, y, f"Customer: {data.customer_name}")
#     y -= 15
#     c.drawString(40, y, f"Email: {data.customer_email}")
#     y -= 30

#     c.setFillColor(colors.lightgrey)
#     c.rect(40, y, w - 80, 20, fill=1)
#     c.setFillColor(colors.black)

#     c.drawString(50, y + 5, "Product")
#     c.drawString(250, y + 5, "Qty")
#     c.drawString(300, y + 5, "Price")
#     c.drawString(380, y + 5, "Total")
#     y -= 25

#     for it in items:
#         c.drawString(50, y, it["name"])
#         c.drawString(250, y, str(it["qty"]))
#         c.drawString(300, y, f"{it['price']}")
#         c.drawString(380, y, f"{it['total']}")
#         y -= 20

#     y -= 10
#     c.setFont("Helvetica-Bold", 12)
#     c.drawRightString(w - 40, y, f"Grand Total: {grand_total}")

#     c.save()
#     return path

# # ======================================================
# # SCHEMAS
# # ======================================================
# class PurchaseData(BaseModel):
#     supplier_id: int
#     quantity: int
#     buy_price: float

# class SellItem(BaseModel):
#     product_id: int
#     quantity: int
#     sell_price: float

# class SellMultiData(BaseModel):
#     items: List[SellItem]
#     customer_name: str
#     customer_phone: str
#     customer_email: str

# # ======================================================
# # SUPPLIER CRUD
# # ======================================================
# @app.post("/supplier")
# async def add_supplier(data: supplier_pydanticIn, user: User = Depends(get_current_user)):
#     obj = await Supplier.create(**data.dict(), user_id=user.id)
#     return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(obj)}

# @app.get("/supplier")
# async def get_suppliers(user: User = Depends(get_current_user)):
#     return {
#         "status": "ok",
#         "data": await supplier_pydantic.from_queryset(
#             Supplier.filter(user_id=user.id)
#         )
#     }

# @app.put("/supplier/{supplier_id}")
# async def update_supplier(
#     supplier_id: int,
#     data: dict = Body(...),
#     user: User = Depends(get_current_user)
# ):
#     supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()
#     if not supplier:
#         raise HTTPException(404, "Supplier not found")

#     for k, v in data.items():
#         if hasattr(supplier, k):
#             setattr(supplier, k, v)

#     await supplier.save()
#     return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(supplier)}

# @app.delete("/supplier/{supplier_id}")
# async def delete_supplier(supplier_id: int, user: User = Depends(get_current_user)):
#     await Supplier.filter(id=supplier_id, user_id=user.id).delete()
#     return {"status": "ok"}

# # ======================================================
# # PRODUCT CRUD
# # ======================================================
# @app.post("/product/{supplier_id}")
# async def add_product(
#     supplier_id: int,
#     data: product_pydanticIn,
#     user: User = Depends(get_current_user)
# ):
#     supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()
#     if not supplier:
#         raise HTTPException(404, "Supplier not found")

#     d = data.dict(exclude_unset=True)
#     d["revenue"] = d.get("quantity_sold", 0) * d.get("unit_price", 0)
#     d["net_profit"] = d.get("profit_per_piece", 0) * d.get("quantity_sold", 0)

#     obj = await Products.create(**d, supplied_by=supplier, user_id=user.id)
#     return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(obj)}

# # @app.get("/product")
# # async def get_products(user: User = Depends(get_current_user)):
# #     products = await Products.filter(user_id=user.id).prefetch_related("supplied_by")
# #     out = []
# #     for p in products:
# #         d = (await product_pydantic.from_tortoise_orm(p)).dict()
# #         d["supplied_by_id"] = p.supplied_by_id
# #         out.append(d)
# #     return {"status": "ok", "data": out}
# @app.get("/product")
# async def get_products(user: User = Depends(get_current_user)):
#     products = await Products.filter(user_id=user.id).prefetch_related("supplied_by")

#     out = []
#     for p in products:
#         out.append({
#             "id": p.id,
#             "name": p.name,
#             "quantity_in_stock": p.quantity_in_stock,
#             "quantity_sold": p.quantity_sold,
#             "unit_price": str(p.unit_price),
#             "revenue": str(p.revenue),
#             "profit_per_piece": str(p.profit_per_piece),
#             "net_profit": str(p.net_profit),
#             "last_purchase_price": str(p.last_purchase_price),
#             "supplied_by_id": p.supplied_by_id,
#         })

#     return {"status": "ok", "data": out}

# # ======================================================
# # PURCHASE
# # ======================================================
# @app.post("/product/purchase/{product_id}")
# async def purchase_product(
#     product_id: int,
#     data: PurchaseData,
#     user: User = Depends(get_current_user)
# ):
#     product = await Products.filter(id=product_id, user_id=user.id).first()
#     supplier = await Supplier.filter(id=data.supplier_id, user_id=user.id).first()

#     if not product or not supplier:
#         raise HTTPException(404, "Invalid product or supplier")

#     product.quantity_in_stock += data.quantity
#     product.last_purchase_price = Decimal(str(data.buy_price))
#     await product.save()

#     await StockMovement.create(
#         product_id=product.id,
#         movement_type="purchase",
#         quantity=data.quantity,
#         price_per_unit=Decimal(str(data.buy_price)),
#         total_amount=Decimal(str(data.buy_price)) * data.quantity,
#         supplier_id=supplier.id,
#         user_id=user.id
#     )

#     return {"status": "ok"}

# # ======================================================
# # SELL MULTI
# # ======================================================
# @app.post("/product/sell-multi")
# async def sell_multi(data: SellMultiData, user: User = Depends(get_current_user)):
#     invoice = f"INV-{int(datetime.now().timestamp())}"
#     timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")

#     items_out = []
#     grand_total = Decimal("0")

#     async with in_transaction():
#         for item in data.items:
#             product = await Products.filter(
#                 id=item.product_id,
#                 user_id=user.id
#             ).first()

#             if not product:
#                 raise HTTPException(404, f"Product {item.product_id} not found")

#             if product.quantity_in_stock < item.quantity:
#                 raise HTTPException(
#                     400,
#                     f"Insufficient stock for {product.name}"
#                 )

#             price = Decimal(str(item.sell_price))
#             qty = item.quantity
#             total = price * qty

#             # Update product
#             product.quantity_in_stock -= qty
#             product.quantity_sold += qty
#             product.revenue += total
#             product.net_profit += qty * product.profit_per_piece
#             await product.save()

#             # Stock movement
#             await StockMovement.create(
#                 product_id=product.id,
#                 movement_type="sale",
#                 quantity=qty,
#                 price_per_unit=price,
#                 total_amount=total,
#                 customer_name=data.customer_name,
#                 customer_phone=data.customer_phone,
#                 customer_email=data.customer_email,
#                 invoice_number=invoice,
#                 user_id=user.id
#             )

#             items_out.append({
#                 "name": product.name,
#                 "qty": qty,
#                 "price": float(price),
#                 "total": float(total)
#             })

#             grand_total += total

#     # Generate invoice AFTER DB success
#     generate_invoice_pdf_multi(
#         invoice,
#         items_out,
#         grand_total,
#         data,
#         timestamp
#     )

#     return {
#         "status": "ok",
#         "invoice_pdf": f"/download_invoice/{invoice}"
#     }
# # ======================================================
# # DOWNLOAD INVOICE
# # ======================================================
# @app.get("/download_invoice/{invoice}")
# async def download_invoice(invoice: str, user: User = Depends(get_current_user)):
#     path = f"invoices/{invoice}.pdf"
#     if not os.path.exists(path):
#         raise HTTPException(404, "Invoice not found")
#     return FileResponse(path, filename=f"{invoice}.pdf")

# # ======================================================
# # MOVEMENTS
# # ======================================================
# @app.get("/movements")
# async def movements(user: User = Depends(get_current_user)):
#     """
#     Return all stock movements for the current owner with the fields
#     the frontend expects (includes invoice_number and customer info).
#     """
#     out = []
#     for m in await StockMovement.filter(user_id=user.id).order_by("-timestamp"):
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
#             "timestamp": m.timestamp.isoformat(),
#             "invoice_number": m.invoice_number,
#         })
#     return {"status": "ok", "data": out}

# # ======================================================
# # DATABASE
# # ======================================================
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
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Depends, Body, Request
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
    Products, product_pydanticIn,
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

# Preflight handler (IMPORTANT for OAuth + CORS)
@app.options("/{path:path}")
async def preflight_handler(path: str, request: Request):
    return {}

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

def hash_password(p: str):
    return pwd_context.hash(p)

def verify_password(p: str, h: str):
    return pwd_context.verify(p, h)

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
        raise HTTPException(400, "Username exists")

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
    return {"status": "ok", "data": obj.id}

@app.get("/product")
async def get_products(user: User = Depends(get_current_user)):
    products = await Products.filter(user_id=user.id)
    return {
        "status": "ok",
        "data": [
            {
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
            }
            for p in products
        ],
    }

# ======================================================
# DATABASE
# ======================================================
DB_URL = os.getenv("DB_URL")
if not DB_URL:
    raise RuntimeError("DB_URL missing")

register_tortoise(
    app,
    db_url=DB_URL,
    modules={"models": ["models"]},
    generate_schemas=False,
    add_exception_handlers=True,
)

logger.info("✅ Inventory API started")
