import os
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext

from fastapi_mail import FastMail, MessageSchema, MessageType, ConnectionConfig

from tortoise.contrib.fastapi import register_tortoise

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

import logging
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("inventory")
logging.basicConfig(level=logging.INFO)

# Import models
from models import (
    User, User_Pydantic, UserIn_Pydantic,
    Supplier, supplier_pydantic, supplier_pydanticIn,
    Products, product_pydantic, product_pydanticIn,
    StockMovement
)




# FASTAPI + CORS
app = FastAPI(title="Inventory Management API")


origins = [
    "https://inventory-management-frontend-hqhs.onrender.com",  # Render frontend
    "http://localhost:5173",
    "http://localhost:3000",
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


# EMAIL CONFIG (must come from environment; fail fast if missing)
# Support both EMAIL_USER/PASS and legacy EMAIL/PASS env names.
EMAIL = os.getenv("EMAIL_USER") or os.getenv("EMAIL")
PASS = os.getenv("EMAIL_PASS") or os.getenv("PASS")

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
else:
    logger.warning("MAIL_CONF not initialized: missing EMAIL/EMAIL_USER or PASS/EMAIL_PASS env vars")



#################   AUTH CONFIG (JWT)   ###########################
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Generate a temporary secret key for development (NOT for production!)
    import secrets as sec_lib
    SECRET_KEY = sec_lib.token_urlsafe(32)
    logger.warning("⚠️  SECRET_KEY not set in environment. Using temporary key (NOT SECURE FOR PRODUCTION!)")
    logger.warning("⚠️  Set SECRET_KEY in your .env file for production deployments")
else:
    logger.info("✅ SECRET_KEY loaded from environment")

ALGORITHM = "HS256"
# Default token lifetime 30 days (user stays logged in until they logout)
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def verify_password(raw: str, hashed: str) -> bool:
    return pwd_context.verify(raw, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)



# --- SIGNUP (same as before) ---
class SignupSchema(BaseModel):
    username: str
    email: str
    phone: str
    password: str
    full_name: Optional[str] = None


@app.post("/signup")
async def signup(data: SignupSchema):
    """
    Standard signup endpoint. Requires email and phone OTP verification.
    Use /register for mobile-only registration.
    """
    if not data.username or not data.username.strip():
        raise HTTPException(400, "Username is required")
    if not data.email or "@" not in data.email:
        raise HTTPException(400, "Valid email is required")
    if not data.phone or not data.phone.strip():
        raise HTTPException(400, "Phone number is required")
    if not data.password or len(data.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    
    # Check if email and phone are verified
    email_lower = data.email.strip().lower()
    if email_lower not in email_verified_set:
        raise HTTPException(400, "Email not verified. Please verify email OTP first.")
    
    if data.phone not in verified_numbers:
        raise HTTPException(400, "Phone number not verified. Please verify phone OTP first.")
    
    if await User.filter(username=data.username).exists():
        raise HTTPException(400, "Username already exists")
    if await User.filter(email=email_lower).exists():
        raise HTTPException(400, "Email already registered")
    if await User.filter(phone=data.phone).exists():
        raise HTTPException(400, "Phone already registered")

    hashed_pw = hash_password(data.password)

    try:
        user = await User.create(
            username=data.username.strip(),
            email=email_lower,
            phone=data.phone.strip(),
            full_name=data.full_name.strip() if data.full_name else None,
            hashed_password=hashed_pw
        )
        
        # Remove from verified sets after successful registration
        email_verified_set.discard(email_lower)
        verified_numbers.discard(data.phone)
        
        logger.info(f"New user signed up: {user.username} (ID: {user.id})")
        
        return {"status": "ok", "user": await User_Pydantic.from_tortoise_orm(user)}
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(500, "Signup failed. Please try again.")


# --- LOGIN: return access_token with user id in sub ---
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.filter(username=form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(401, "Incorrect username or password")

    token = create_access_token({"sub": str(user.id)})
    # return expiry too (seconds) — useful for frontend if needed
    return {"access_token": token, "token_type": "bearer", "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES}


# --- get_current_user: decodes token and returns user model ---
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


@app.get("/users/me")
async def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "phone": user.phone,
        "full_name": user.full_name
    }


# PDF GENERATOR

# def generate_invoice_pdf_multi(invoice_number, items, grand_total, data, timestamp):
#     os.makedirs("invoices", exist_ok=True)
#     file_path = f"invoices/{invoice_number}.pdf"

#     c = canvas.Canvas(file_path, pagesize=A4)
#     width, height = A4
    
#     left = 25
#     right = width - 25
#     top = height - 30
#     bottom = 50

#     c.roundRect(left, bottom, right - left, top - bottom, 12)

#     y = top - 20

#     c.setFont("Helvetica-Bold", 22)
#     c.drawCentredString(width / 2, y, "MOBILE WORLD LTD")
#     y -= 25

#     c.setFont("Helvetica-Bold", 14)
#     c.drawCentredString(width / 2, y, "TAX INVOICE / BILL")

#     y -= 40
#     c.setFont("Helvetica", 11)
#     c.drawString(left + 30, y, f"Invoice No: {invoice_number}")
#     c.drawRightString(right - 30, y, f"Date: {timestamp}")

#     y -= 20
#     c.drawString(left + 30, y, f"Customer: {data.customer_name}")
#     c.drawRightString(right - 30, y, f"Phone: {data.customer_phone}")

#     y -= 20
#     c.drawString(left + 30, y, f"Email: {data.customer_email}")

#     # table header
#     y -= 40
#     table_width = right - left - 40

#     c.setFillColor(colors.lightgrey)
#     c.rect(left + 20, y - 20, table_width, 25, fill=1)
#     c.setFillColor(colors.black)

#     c.drawString(left + 35, y - 5, "Product")
#     c.drawString(left + 155, y - 5, "Qty")
#     c.drawString(left + 260, y - 5, "Price")
#     c.drawString(left + 370, y - 5, "Total")

#     # table rows
#     y -= 35
#     for i, it in enumerate(items):
#         fill = colors.whitesmoke if i % 2 == 0 else colors.white
#         c.setFillColor(fill)
#         c.rect(left + 20, y - 20, table_width, 25, fill=1)
#         c.setFillColor(colors.black)

#         c.drawString(left + 35, y - 5, it["name"])
#         c.drawString(left + 155, y - 5, str(it["qty"]))
#         c.drawString(left + 260, y - 5, f"{it['price']:,.2f}")
#         c.drawString(left + 370, y - 5, f"{it['total']:,.2f}")

#         y -= 30

#     # grand total
#     c.setFillColor(colors.black)
#     c.line(left + 20, y + 10, right - 20, y + 10)

#     c.setFillColor(colors.lightgrey)
#     c.rect(left + 20, y - 20, table_width, 25, fill=1)
#     c.setFillColor(colors.black)
#     c.setFont("Helvetica-Bold", 12)

#     c.drawString(left + 260, y - 5, "Grand Total")
#     c.drawRightString(right - 30, y - 5, f"{grand_total:,.2f}")

#     c.save()
#     return file_path

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from io import BytesIO
import textwrap, os, qrcode, secrets
from decimal import Decimal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INVOICE_DIR = os.path.join(BASE_DIR, "invoices")


def get_field(obj, field):
    """Safely fetch field from dict or pydantic model."""
    if isinstance(obj, dict):
        return obj.get(field, "")
    return getattr(obj, field, "")


def generate_invoice_pdf_multi(invoice_number, items, grand_total, data, timestamp):

    # 🔥 FIXED: Works on Render using ABSOLUTE PATH
    os.makedirs(INVOICE_DIR, exist_ok=True)
    file_path = os.path.join(INVOICE_DIR, f"{invoice_number}.pdf")

    PAGE_WIDTH, PAGE_HEIGHT = A4
    left = 30
    right = PAGE_WIDTH - 30
    top = PAGE_HEIGHT - 30
    bottom = 40
    content_width = right - left
    line_height = 14

    grand_total = float(grand_total)

    c = canvas.Canvas(file_path, pagesize=A4)

    def draw_header():
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(PAGE_WIDTH/2, top - 10, "MOBILE WORLD LTD")

        c.setFont("Helvetica", 10)
        c.drawCentredString(PAGE_WIDTH/2, top - 28, "Premium Mobile Devices & Accessories")
        c.drawCentredString(PAGE_WIDTH/2, top - 42, "123 Roorkee, Haridwar, Uttarakhand 560001 | Phone: +91-8012345678")

        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(PAGE_WIDTH/2, top - 56, "GSTIN: 29ABCDE1234F1Z5 | PAN: ABCDE1234F")

        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(PAGE_WIDTH/2, top - 82, "TAX INVOICE")
        c.line(PAGE_WIDTH/2 - 60, top - 84, PAGE_WIDTH/2 + 60, top - 84)

    draw_header()

    y = top - 120
    box_h = 70
    half = content_width / 2 - 10

    c.setFillColor(colors.whitesmoke)
    c.rect(left, y-box_h, half, box_h, fill=1)
    c.rect(left + half + 20, y-box_h, half, box_h, fill=1)

    c.setFillColor(colors.black)
    c.rect(left, y-box_h, half, box_h)
    c.rect(left + half + 20, y-box_h, half, box_h)

    cname = get_field(data, "customer_name")
    cemail = get_field(data, "customer_email")
    cphone = get_field(data, "customer_phone")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(left + 10, y - 15, "BILL TO:")

    c.setFont("Helvetica", 9)
    c.drawString(left + 10, y - 32, cname)
    c.drawString(left + 10, y - 46, cemail)
    c.drawString(left + 10, y - 60, f"Phone: {cphone}")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(left + half + 30, y - 15, "INVOICE DETAILS:")

    c.setFont("Helvetica", 9)
    c.drawString(left + half + 30, y - 32, f"Invoice No: {invoice_number}")
    c.drawString(left + half + 30, y - 46, f"Date: {timestamp}")
    c.drawString(left + half + 30, y - 60, "Place of Supply: Roorkee")

    y -= (box_h + 40)

    col = {
        "sno": left + 10,
        "product": left + 60,
        "hsn": left + 250,
        "qty": left + 330,
        "rate": left + 400,
        "amount": left + 480,
    }

    c.setFillColor(colors.lightgrey)
    c.rect(left, y - 22, content_width, 22, fill=1, stroke=0)

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(col["sno"], y - 14, "S.No.")
    c.drawString(col["product"], y - 14, "PRODUCT")
    c.drawString(col["hsn"], y - 14, "HSN")
    c.drawString(col["qty"], y - 14, "QTY")
    c.drawString(col["rate"], y - 14, "RATE")
    c.drawString(col["amount"], y - 14, "AMOUNT")

    y -= 30

    total_qty = 0

    def ensure_space(lines=1):
        nonlocal y
        if y < bottom + 200:
            c.showPage()
            draw_header()
            _draw_table_header()

    def _draw_table_header():
        nonlocal y
        y = top - 140
        c.setFillColor(colors.lightgrey)
        c.rect(left, y - 22, content_width, 22, fill=1)
        c.setFillColor(colors.black)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(col["sno"], y - 14, "S.No.")
        c.drawString(col["product"], y - 14, "PRODUCT")
        c.drawString(col["hsn"], y - 14, "HSN")
        c.drawString(col["qty"], y - 14, "QTY")
        c.drawString(col["rate"], y - 14, "RATE")
        c.drawString(col["amount"], y - 14, "AMOUNT")
        y -= 30

    for i, item in enumerate(items):

        pname = str(item.get("name"))
        wrapped = textwrap.wrap(pname, width=40)
        needed = max(1, len(wrapped))
        ensure_space(needed)

        row_h = needed * line_height + 8

        fill = colors.white if i % 2 == 0 else colors.whitesmoke
        c.setFillColor(fill)
        c.rect(left, y - row_h + 4, content_width, row_h, fill=1)

        c.setStrokeColor(colors.grey)
        c.rect(left, y - row_h + 4, content_width, row_h)

        c.setFillColor(colors.black)
        c.setFont("Helvetica", 9)
        c.drawString(col["sno"], y - 2, str(i+1))

        ty = y
        for part in wrapped:
            c.drawString(col["product"], ty, part)
            ty -= line_height

        qty = int(item.get("qty"))
        rate = float(item.get("price"))
        amt = float(item.get("total"))

        c.drawString(col["hsn"], y - 2, item.get("hsn_code", "N/A"))
        c.drawString(col["qty"], y - 2, str(qty))
        c.drawString(col["rate"], y - 2, f"{rate:,.2f}")
        c.drawRightString(col["amount"] + 40, y - 2, f"{amt:,.2f}")

        total_qty += qty
        y -= (row_h + 6)

    ensure_space(2)

    c.setFillColor(colors.lightgrey)
    c.rect(left, y - 22, content_width, 22, fill=1)
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(col["product"], y - 14, "TOTAL")
    c.drawString(col["qty"], y - 14, str(total_qty))
    c.drawRightString(col["amount"] + 40, y - 14, f"{grand_total:,.2f}")

    y -= 40

    cgst = grand_total * 0.09
    sgst = grand_total * 0.09
    tax_total = cgst + sgst
    payable = grand_total + tax_total

    c.setFont("Helvetica-Bold", 11)
    c.drawString(left, y, "GST Breakup")
    y -= 20

    gst_list = [
        ("CGST (9%)", cgst),
        ("SGST (9%)", sgst),
        ("Total Tax", tax_total),
        ("Grand Total (Incl. Tax)", payable)
    ]

    c.setFont("Helvetica", 10)
    for label, val in gst_list:
        c.drawString(left, y, label)
        c.drawRightString(right - 10, y, f"₹{val:,.2f}")
        y -= 16

    y -= 10

    qr_data = f"upi://pay?pa=7830424458@slc&pn=MobileWorld&am={payable}&cu=INR"
    qr_img = qrcode.make(qr_data)
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    qr_reader = ImageReader(qr_buffer)

    c.setFont("Helvetica-Bold", 11)
    c.drawString(left, y, "Scan to Pay")

    c.drawImage(qr_reader, left, y - 130, width=120, height=120)

    y -= 150
    c.setFont("Helvetica-Bold", 10)
    c.drawString(left, y, "Terms & Conditions:")

    terms = [
        "1. Goods once sold will not be taken back.",
        "2. Warranty as per manufacturer’s terms.",
        "3. Payment due within 15 days.",
        "4. Interest @18% p.a. after due date.",
        "5. Bengaluru jurisdiction applies."
    ]

    y -= 15
    c.setFont("Helvetica", 9)
    for t in terms:
        c.drawString(left + 10, y, t)
        y -= 12

    sig_y = bottom + 70
    c.line(PAGE_WIDTH/2 + 20, sig_y, PAGE_WIDTH/2 + 150, sig_y)
    c.drawString(PAGE_WIDTH/2 + 40, sig_y - 12, "Authorized Signatory")

    c.setFont("Helvetica", 8)
    c.drawCentredString(PAGE_WIDTH/2, bottom + 20,
                        "This is a computer generated invoice and does not require a signature.")

    c.save()
    return file_path



####################   SCHEMAS   #########################
class PurchaseData(BaseModel):
    supplier_id: int
    quantity: int
    buy_price: float


class SellItem(BaseModel):
    product_id: int
    quantity: int
    sell_price: float


class SellData(BaseModel):
    quantity: int
    sell_price: float
    customer_name: str
    customer_phone: str
    customer_email: str


class SellMultiData(BaseModel):
    items: List[SellItem]
    customer_name: str
    customer_phone: str
    customer_email: str




###################   Purchase Product   #############################
@app.post("/product/purchase/{product_id}")
async def purchase_product(
    product_id: int,
    data: PurchaseData,
    user: User = Depends(get_current_user)       # 👈 REQUIRED for multi-user
):

    # Ensure product belongs to logged-in user
    product = await Products.get_or_none(id=product_id, user_id=user.id)
    if not product:
        raise HTTPException(404, "Product not found for this user")


    # Ensure supplier belongs to logged-in user
    supplier = await Supplier.get_or_none(id=data.supplier_id, user_id=user.id)
    if not supplier:
        raise HTTPException(400, "Invalid supplier id")

    if data.quantity <= 0:
        raise HTTPException(400, "Quantity must be > 0")
    if data.buy_price <= 0:
        raise HTTPException(400, "Buy price must be > 0")


    # UPDATE PRODUCT
    product.quantity_in_stock += data.quantity
    product.last_purchase_price = Decimal(str(data.buy_price))
    product.supplied_by_id = data.supplier_id
    await product.save()

    total_amount = Decimal(str(data.buy_price)) * data.quantity


    # Create stock movement with user scoping
    await StockMovement.create(
        product_id=product_id,
        movement_type="purchase",
        quantity=data.quantity,
        price_per_unit=Decimal(str(data.buy_price)),
        total_amount=total_amount,
        supplier_id=data.supplier_id,
        user_id=user.id,
    )

    timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")


    # EMAIL
    if MAIL_CONF:
        fm = FastMail(MAIL_CONF)

        html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">

            <h2 style="color: #1a73e8; margin-bottom: 10px;">Purchase Confirmation</h2>

            <p style="font-size: 15px;">
                Hello <strong style="color:#000;">{supplier.name}</strong>,
            </p>

            <p style="font-size: 15px; line-height: 1.6;">
                This email confirms that Mobile World LTD has successfully purchased the following stock 
                from your company <strong>{supplier.company}</strong>:
            </p>

            <div style="
                margin: 20px 0; 
                padding: 15px; 
                background: #f1f9ff; 
                border-left: 4px solid #1a73e8;
                border-radius: 4px;
            ">
                <p style="margin: 0; font-size: 14px; line-height: 1.6;">
                    <strong>Product:</strong> {product.name}<br>
                    <strong>Quantity:</strong> {data.quantity}<br>
                    <strong>Price Per Unit:</strong> {Decimal(str(data.buy_price)):,.2f}<br>
                    <strong>Total Amount:</strong> {total_amount:,.2f}<br>
                    <strong>Date:</strong> {timestamp}
                </p>
            </div>

            <p style="font-size: 14px; line-height: 1.6;">
                Thank you for your cooperation and consistent supply. 
                If you have any questions regarding this purchase, 
                feel free to reply to this email.
            </p>

            <br>

            <p style="font-size: 15px; font-weight: bold; color: #444;">
                — Mobile World LTD Procurement Team
            </p>

            <p style="font-size: 13px; color: #888; margin-top: 10px;">
                This is an automated purchase confirmation email.
            </p>

        </div>
        """

        message = MessageSchema(
            subject=f"Purchase Confirmation - {product.name}",
            recipients=[supplier.email],
            body=html,
            subtype=MessageType.html,
        )

        try:
            await fm.send_message(message)
        except Exception as e:
            print("EMAIL ERROR:", e)

    return {"status": "ok", "product": await product_pydantic.from_tortoise_orm(product)}

 
####################     Sell Api    ############################
@app.post("/product/sell")
async def sell_products(
    data: SellMultiData,
    user: User = Depends(get_current_user)     # 👈 REQUIRED for multi-user
):

    items_out = []
    updates = []
    grand_total = Decimal("0")

    invoice_number = f"INV-{int(datetime.now().timestamp())}"

    for item in data.items:

        # 🔥 Ensure product belongs to THIS USER
        product = await Products.get_or_none(id=item.product_id, user_id=user.id)
        if not product:
            raise HTTPException(404, "Product not found for this user")

        if product.quantity_in_stock < item.quantity:
            raise HTTPException(400, f"Not enough stock for {product.name}")
        if item.quantity <= 0:
            raise HTTPException(400, "Quantity must be > 0")
        if item.sell_price <= 0:
            raise HTTPException(400, "Sell price must be > 0")

        price = Decimal(str(item.sell_price))
        total = price * item.quantity

        items_out.append({
            "name": product.name,
            "qty": item.quantity,
            "price": price,
            "total": total
        })

        updates.append((product, item.quantity, price))
        grand_total += total

    for product, qty, price in updates:

        product.quantity_in_stock -= qty
        product.quantity_sold += qty
        product.revenue += qty * price
        product.net_profit += qty * product.profit_per_piece
        product.last_sale_price = price
        await product.save()

        # 🔥 Movement also must store user_id
        await StockMovement.create(
            product_id=product.id,
            movement_type="sale",
            quantity=qty,
            price_per_unit=price,
            total_amount=qty * price,
            customer_name=data.customer_name,
            customer_phone=data.customer_phone,
            customer_email=data.customer_email,
            invoice_number=invoice_number,
            user_id=user.id
        )

    # Creating Invoice Pdf
    timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    pdf_path = generate_invoice_pdf_multi(
        invoice_number,
        items_out,
        grand_total,
        data,
        timestamp
    )

    #EMAIL
    if MAIL_CONF:
        fm = FastMail(MAIL_CONF)

        html = f"""
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #333;">

            <h2 style="color: #1a73e8; margin-bottom: 10px;">Thank you for your purchase!</h2>

            <p style="font-size: 15px;">
                Hello <strong style="color:#000;">{data.customer_name}</strong>,
            </p>

            <p style="font-size: 15px; line-height: 1.6;">
                We truly appreciate your business. Your invoice has been generated and is attached to this email for your convenience.
            </p>

            <div style="
                margin: 20px 0; 
                padding: 15px; 
                background: #f1f9ff; 
                border-left: 4px solid #1a73e8;
                border-radius: 4px;
            ">
                <p style="margin: 0; font-size: 14px; line-height: 1.6;">
                    <strong>Invoice Number:</strong> {invoice_number}<br>
                    <strong>Date:</strong> {timestamp}<br>
                    <strong>Total Items:</strong> {len(items_out)}<br>
                    <strong>Grand Total:</strong> {grand_total:,.2f}
                </p>
            </div>

            <p style="font-size: 14px; line-height: 1.6;">
                If you have any questions regarding this order or invoice, feel free to reply to this email — 
                we are always happy to help!
            </p>

            <br>

            <p style="font-size: 15px; font-weight: bold; color: #444;">
                — Mobile World LTD Team
            </p>

            <p style="font-size: 13px; color: #888; margin-top: 10px;">
                Thank you for choosing Mobile World LTD!
            </p>

        </div>
        """

        msg = MessageSchema(
            subject=f"Invoice - {invoice_number}",
            recipients=[data.customer_email],
            body=html,
            subtype=MessageType.html,
            attachments=[pdf_path]
        )

        try:
            await fm.send_message(msg)
        except Exception as e:
            print("EMAIL ERROR:", e)

    return {
        "status": "ok",
        "invoice_pdf": f"/download_invoice/{invoice_number}"
    }


##################### Download Invoice PDF   #####################################
@app.get("/download_invoice/{invoice_number}")
async def download_invoice(
    invoice_number: str,
    user: User = Depends(get_current_user)
):
    """
    Download invoice PDF. Only allows access to invoices created by the authenticated user.
    """
    # Find the stock movement with this invoice number for this user
    movement = await StockMovement.filter(
        invoice_number=invoice_number,
        user_id=user.id
    ).first()
    
    if not movement:
        raise HTTPException(404, "Invoice not found or access denied")
    
    # Construct file path
    file_path = os.path.join(INVOICE_DIR, f"{invoice_number}.pdf")
    
    if not os.path.exists(file_path):
        raise HTTPException(404, "Invoice file not found")
    
    return FileResponse(
        file_path,
        media_type="application/pdf",
        filename=f"invoice_{invoice_number}.pdf"
    )


##################### Download Pdf   #####################################
@app.get("/product/{product_id}/movements")
async def product_movements(
    product_id: int,
    user: User = Depends(get_current_user)  
):
    # Only fetch movements created by this user
    moves = await StockMovement.filter(
        product_id=product_id,
        user_id=user.id                   
    ).order_by("-timestamp")

    out = []

    for m in moves:
        try:
            prod = await m.product
            product_name = prod.name if prod else None
        except Exception:
            product_name = None

        supplier_name = None
        try:
            sup = await m.supplier
            supplier_name = sup.name if sup else None
        except Exception:
            supplier_name = None

        ts = None
        try:
            ts = m.timestamp.isoformat(sep=" ")
        except:
            ts = str(m.timestamp)

        invoice_pdf = None
        inv_num = getattr(m, "invoice_number", None)
        if inv_num:
            invoice_pdf = f"/download_invoice/{inv_num}"

        out.append({
            "id": m.id,
            "product_id": m.product_id,
            "product_name": product_name,
            "movement_type": m.movement_type,
            "quantity": m.quantity,
            "price_per_unit": str(m.price_per_unit),
            "total_amount": str(m.total_amount),
            "supplier_id": m.supplier_id,
            "supplier_name": supplier_name,
            "customer_name": m.customer_name,
            "customer_phone": m.customer_phone,
            "customer_email": m.customer_email,
            "timestamp": ts,
            "invoice_pdf": invoice_pdf
        })

    return {"status": "ok", "data": out}




@app.get("/movements")
async def all_movements(user: User = Depends(get_current_user)):

    items = await StockMovement.filter(
        user_id=user.id        # 👈 show only user's movements
    ).order_by("-timestamp")

    out = []

    for m in items:
        try:
            product_obj = await m.product
            product_name = product_obj.name if product_obj else None
        except:
            product_name = None

        invoice_number = getattr(m, "invoice_number", None)

        out.append({
            "id": m.id,
            "product_id": m.product_id,
            "product_name": product_name,
            "movement_type": m.movement_type,
            "quantity": m.quantity,
            "price_per_unit": str(m.price_per_unit),
            "total_amount": str(m.total_amount),
            "supplier_id": m.supplier_id,
            "customer_name": m.customer_name,
            "customer_phone": m.customer_phone,
            "customer_email": m.customer_email,
            "timestamp": str(m.timestamp),
            "invoice_number": invoice_number
        })

    return {"status": "ok", "data": out}






############################   Supplier Crud   ################################
@app.post("/supplier")
async def add_supplier(
    data: supplier_pydanticIn,
    user: User = Depends(get_current_user)  
):
    obj = await Supplier.create(
        **data.dict(exclude_unset=True),
        user_id=user.id                     
    )
    logger.info("Supplier created by user_id=%s id=%s", user.id, obj.id)
    return {
        "status": "ok",
        "data": await supplier_pydantic.from_tortoise_orm(obj)
    }



@app.get("/supplier")
async def get_suppliers(user: User = Depends(get_current_user)):   
    query = Supplier.filter(user_id=user.id).order_by("id")        
    data = await supplier_pydantic.from_queryset(query)
    return {"status": "ok", "data": data}



@app.get("/supplier/{id}")
async def get_supplier(id: int, user: User = Depends(get_current_user)):  

    sup = await Supplier.filter(id=id, user_id=user.id).first()    
    if not sup:
        raise HTTPException(404, "Supplier not found")

    return {
        "status": "ok",
        "data": await supplier_pydantic.from_tortoise_orm(sup)
    }



@app.put("/supplier/{id}")
async def update_supplier(
    id: int,
    data: supplier_pydanticIn = Body(...),
    user: User = Depends(get_current_user)    
):
    supplier = await Supplier.filter(id=id, user_id=user.id).first()  
    if not supplier:
        raise HTTPException(404, "Supplier not found")

    upd = data.dict(exclude_unset=True)
    for key, value in upd.items():
        if hasattr(supplier, key):
            setattr(supplier, key, value)

    await supplier.save()

    return {
        "status": "ok",
        "data": await supplier_pydantic.from_tortoise_orm(supplier)
    }



@app.delete("/supplier/{id}")
async def delete_supplier(id: int, user: User = Depends(get_current_user)):   # NEW
    deleted = await Supplier.filter(id=id, user_id=user.id).delete()          # NEW

    if not deleted:
        raise HTTPException(404, "Supplier not found")

    return {"status": "ok"}


############################   Product Crud   ################################

@app.post("/product/{supplier_id}")
async def add_product(
    supplier_id: int,
    data: product_pydanticIn,
    user: User = Depends(get_current_user)       # NEW
):
    supplier = await Supplier.filter(id=supplier_id, user_id=user.id).first()  # NEW
    if not supplier:
        raise HTTPException(404, "Supplier not found")

    d = data.dict(exclude_unset=True)
    d["revenue"] = d.get("quantity_sold", 0) * d.get("unit_price", 0)
    d["net_profit"] = d.get("profit_per_piece", 0) * d.get("quantity_sold", 0)

    obj = await Products.create(
        **d,
        supplied_by=supplier,
        user_id=user.id                        # NEW
    )
    logger.info("Product created by user_id=%s id=%s", user.id, obj.id)

    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(obj)}



@app.get("/product")
async def get_products(user: User = Depends(get_current_user)):     # NEW

    products = (
        await Products.filter(user_id=user.id)                     # NEW
        .order_by("id")
        .prefetch_related("supplied_by")
    )

    data = []
    for p in products:
        item = await product_pydantic.from_tortoise_orm(p)
        d = item.dict()
        d["supplied_by_id"] = p.supplied_by_id
        data.append(d)

    return {"status": "ok", "data": data}



@app.get("/product/{id}")
async def get_product(id: int, user: User = Depends(get_current_user)):     # NEW

    product = await Products.filter(id=id, user_id=user.id).first()        # NEW
    if not product:
        raise HTTPException(404, "Product not found")

    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(product)}



@app.put("/product/{id}")
async def update_product(
    id: int,
    data: product_pydanticIn,
    user: User = Depends(get_current_user)          # NEW
):
    p = await Products.filter(id=id, user_id=user.id).first()      # NEW
    if not p:
        raise HTTPException(404, "Product not found")

    upd = data.dict(exclude_unset=True)
    for k, v in upd.items():
        setattr(p, k, v)

    p.revenue = p.quantity_sold * p.unit_price
    p.net_profit = p.profit_per_piece * p.quantity_sold

    await p.save()

    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(p)}



@app.delete("/product/{id}")
async def delete_product(id: int, user: User = Depends(get_current_user)):    # NEW

    deleted = await Products.filter(id=id, user_id=user.id).delete()         # NEW

    if not deleted:
        raise HTTPException(404, "Product not found")

    return {"status": "ok"}








#######################   Database Init   ###########################
DB_URL = os.getenv("DB_URL")

if not DB_URL:
    error_msg = (
        "❌ DB_URL missing in environment variables.\n"
        "Please set DB_URL in your .env file.\n"
        "Example: DB_URL=postgres://user:password@localhost:5432/dbname"
    )
    logger.error(error_msg)
    raise Exception(error_msg)

logger.info("✅ Database URL configured")
register_tortoise(
    app,
    db_url=DB_URL,
    modules={"models": ["models"]},
    generate_schemas=False,  # Set to True if you want auto-generate schemas on startup
    add_exception_handlers=True,
)
logger.info("✅ Database connection initialized")





#-----------OTP API for mobile----------

OTP_TTL_MINUTES = 5
verified_numbers = set()   # store verified mobiles
mobile_otp_store = {}
# Rate limiting: track last OTP request time per mobile
otp_rate_limit = {}


class OTPRequest(BaseModel):
    mobile: str


class OTPVerifyRequest(BaseModel):
    mobile: str
    otp: int


class RegisterRequest(BaseModel):
    name: str
    mobile: str
    password: str


def _generate_otp() -> int:
    # 6-digit random OTP (100000 to 999999)
    return 100000 + secrets.randbelow(900000)


@app.post("/send-otp")
def send_otp(data: OTPRequest):
    if not data.mobile or not data.mobile.strip():
        raise HTTPException(400, "Mobile number is required")
    
    # Basic rate limiting: max 1 OTP per minute per mobile
    now = datetime.now(timezone.utc)
    last_request = otp_rate_limit.get(data.mobile)
    if last_request and (now - last_request).total_seconds() < 60:
        raise HTTPException(429, "Please wait before requesting another OTP")
    
    otp = _generate_otp()
    expires = now + timedelta(minutes=OTP_TTL_MINUTES)
    mobile_otp_store[data.mobile] = {"otp": otp, "expires": expires}
    otp_rate_limit[data.mobile] = now
    
    # In production, send SMS here using a service like Twilio, AWS SNS, etc.
    # For now, log it (remove in production or use proper SMS service)
    logger.info(f"OTP for {data.mobile}: {otp} (expires in {OTP_TTL_MINUTES} minutes)")
    
    return {
        "message": "OTP sent successfully",
        "expires_in_minutes": OTP_TTL_MINUTES
    }


@app.post("/verify-otp")
def verify_otp(data: OTPVerifyRequest):
    if not data.mobile or not data.mobile.strip():
        raise HTTPException(400, "Mobile number is required")
    
    if not data.otp or data.otp < 100000 or data.otp > 999999:
        raise HTTPException(400, "Invalid OTP format")
    
    entry = mobile_otp_store.get(data.mobile)
    if not entry:
        raise HTTPException(400, "OTP not found. Please request a new OTP")
    
    if entry["expires"] < datetime.now(timezone.utc):
        mobile_otp_store.pop(data.mobile, None)
        raise HTTPException(400, "OTP has expired. Please request a new one")
    
    if data.otp != entry["otp"]:
        # Don't reveal if OTP exists but is wrong vs doesn't exist
        raise HTTPException(400, "Invalid OTP")
    
    # OTP verified successfully
    mobile_otp_store.pop(data.mobile, None)
    verified_numbers.add(data.mobile)
    return {"verified": True, "message": "Mobile number verified successfully"}


@app.post("/register")
async def register_user(data: RegisterRequest):
    """
    Register a new user with mobile OTP verification.
    Note: This endpoint is for mobile-only registration.
    For email-based registration, use /signup endpoint.
    """
    if not data.mobile or not data.mobile.strip():
        raise HTTPException(status_code=400, detail="Mobile number is required")
    
    if not data.name or not data.name.strip():
        raise HTTPException(status_code=400, detail="Name is required")
    
    if not data.password or len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    if data.mobile not in verified_numbers:
        raise HTTPException(status_code=400, detail="Mobile number not verified. Please verify OTP first.")

    if await User.filter(username=data.mobile).exists():
        raise HTTPException(status_code=400, detail="User already exists for this mobile number")
    
    auto_email = f"{data.mobile}@auto.com"
    if await User.filter(email=auto_email).exists():
        raise HTTPException(status_code=400, detail="Email already exists for this mobile")

    hashed = hash_password(data.password)

    try:
        user = await User.create(
            username=data.mobile,   
            email=auto_email, 
            phone=data.mobile,
            full_name=data.name.strip(),
            hashed_password=hashed
        )
        
        # Remove from verified set after successful registration
        verified_numbers.discard(data.mobile)
        
        logger.info(f"New user registered: {user.username} (ID: {user.id})")
        
        return {
            "message": "User registered successfully",
            "user": await User_Pydantic.from_tortoise_orm(user)
        }
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed. Please try again.")


#-----------OTP API for mail-------------------

# email_otp_store = {}


# from random import randint

# @app.post("/send-email-otp")
# async def send_email_otp(email: str):
#     if not MAIL_CONF:
#         raise HTTPException(500, "Email server not configured")

#     otp = randint(100000, 999999)
#     email_otp_store[email] = otp

#     fm = FastMail(MAIL_CONF)

#     html = f"""
#     <h3>Your Email Verification OTP</h3>
#     <p>Your OTP is: <strong>{otp}</strong></p>
#     <p>This OTP will expire in 5 minutes.</p>
#     """

#     message = MessageSchema(
#         subject="Email OTP Verification",
#         recipients=[email],
#         body=html,
#         subtype="html"
#     )

#     try:
#         await fm.send_message(message)
#     except Exception as e:
#         print("Email error:", e)
#         raise HTTPException(500, "Failed to send OTP email")

#     return {"status": "ok", "message": "OTP sent to email"}



# @app.post("/verify-email-otp")
# async def verify_email_otp(email: str, otp: int):
#     real_otp = email_otp_store.get(email)

#     if not real_otp:
#         raise HTTPException(400, "OTP expired or not found")

#     if real_otp != otp:
#         raise HTTPException(400, "Invalid OTP")

#     # OTP is correct — remove it
#     del email_otp_store[email]

#     return {"status": "ok", "verified": True}


email_otp_store = {}
email_verified_set = set()  # Track verified emails
EMAIL_OTP_TTL_MINUTES = 5
email_otp_rate_limit = {}  # Rate limiting for email OTP


# Pydantic Models MUST come before routes
class EmailRequest(BaseModel):
    email: str

class EmailVerifyRequest(BaseModel):
    email: str
    otp: int


@app.post("/send-email-otp")
async def send_email_otp(payload: EmailRequest):
    if not MAIL_CONF:
        raise HTTPException(500, "Email server not configured")

    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "Valid email address is required")
    
    # Basic rate limiting: max 1 OTP per minute per email
    now = datetime.now(timezone.utc)
    last_request = email_otp_rate_limit.get(email)
    if last_request and (now - last_request).total_seconds() < 60:
        raise HTTPException(429, "Please wait before requesting another OTP")
    
    otp = _generate_otp()
    expires = now + timedelta(minutes=EMAIL_OTP_TTL_MINUTES)
    email_otp_store[email] = {"otp": otp, "expires": expires}
    email_otp_rate_limit[email] = now

    fm = FastMail(MAIL_CONF)

    html = f"""
    <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1a73e8;">Email Verification OTP</h2>
        <p>Your verification code is:</p>
        <div style="background: #f1f9ff; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h1 style="color: #1a73e8; margin: 0; letter-spacing: 5px;">{otp}</h1>
        </div>
        <p style="color: #666;">This OTP will expire in {EMAIL_OTP_TTL_MINUTES} minutes.</p>
        <p style="color: #999; font-size: 12px;">If you didn't request this code, please ignore this email.</p>
    </div>
    """

    message = MessageSchema(
        subject="Email OTP Verification - Inventory Management",
        recipients=[email],
        body=html,
        subtype=MessageType.html
    )

    try:
        await fm.send_message(message)
        logger.info(f"Email OTP sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send email OTP to {email}: {e}")
        # Remove the OTP from store if email failed
        email_otp_store.pop(email, None)
        raise HTTPException(500, "Failed to send OTP email. Please try again later.")

    return {
        "status": "ok",
        "message": "OTP sent successfully to your email",
        "expires_in_minutes": EMAIL_OTP_TTL_MINUTES
    }


@app.post("/verify-email-otp")
async def verify_email_otp(payload: EmailVerifyRequest):
    email = payload.email.strip().lower()
    otp = payload.otp

    if not email or "@" not in email:
        raise HTTPException(400, "Valid email address is required")
    
    if not otp or otp < 100000 or otp > 999999:
        raise HTTPException(400, "Invalid OTP format")

    stored = email_otp_store.get(email)

    if not stored:
        raise HTTPException(400, "OTP not found. Please request a new OTP")

    if stored["expires"] < datetime.now(timezone.utc):
        email_otp_store.pop(email, None)
        raise HTTPException(400, "OTP has expired. Please request a new one")

    if otp != stored["otp"]:
        raise HTTPException(400, "Invalid OTP")

    # OTP verified successfully
    email_otp_store.pop(email, None)
    email_verified_set.add(email)

    return {
        "status": "ok",
        "verified": True,
        "message": "Email verified successfully"
    }