import os
from typing import List, Optional
from datetime import datetime, timedelta
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

from dotenv import load_dotenv
load_dotenv()

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
    "https://inventory-management-ero4.onrender.com",  # Render frontend
    "http://localhost:5173",                            # Local React dev
    "http://localhost:3000",                            # Optional (React alt port)
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


# EMAIL CONFIG 
EMAIL = os.getenv("EMAIL")
PASS = os.getenv("PASS")

if not EMAIL or not PASS:
    raise Exception("❌ EMAIL or PASS not found in .env — Email sending cannot work!")

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


#################   AUTH CONFIG (JWT)   ###########################
SECRET_KEY = os.getenv("SECRET_KEY") or "super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def verify_password(raw, hashed):
    return pwd_context.verify(raw, hashed)


def hash_password(raw):
    return pwd_context.hash(raw)


def create_access_token(data: dict, expires: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)



# SIGNUP / LOGIN
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

    if await User.filter(email=data.email).exists():
        raise HTTPException(400, "Email already registered")

    if await User.filter(phone=data.phone).exists():
        raise HTTPException(400, "Phone already registered")

    hashed = hash_password(data.password)

    user = await User.create(
        username=data.username,
        email=data.email,
        phone=data.phone,
        full_name=data.full_name,
        hashed_password=hashed
    )

    return {"status": "ok", "user": await User_Pydantic.from_tortoise_orm(user)}


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.filter(username=form_data.username).first()

    if not user:
        raise HTTPException(401, "Incorrect username or password")

    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(401, "Incorrect username or password")

    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = data.get("sub")
        user = await User.filter(username=username).first()
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except:
        raise HTTPException(401, "Invalid token")


@app.get("/users/me")
async def me(user: User = Depends(get_current_user)):
    return {
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
from reportlab.lib.units import mm
import textwrap, os, qrcode
from decimal import Decimal


def get_field(obj, field):
    """Safely fetch field from dict or pydantic model."""
    if isinstance(obj, dict):
        return obj.get(field, "")
    return getattr(obj, field, "")


def generate_invoice_pdf_multi(invoice_number, items, grand_total, data, timestamp):
    os.makedirs("invoices", exist_ok=True)
    file_path = f"invoices/{invoice_number}.pdf"

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
        c.drawCentredString(PAGE_WIDTH/2, top - 28,
                            "Premium Mobile Devices & Accessories")
        c.drawCentredString(PAGE_WIDTH/2, top - 42,
                            "123 Roorkee, Haridwar, Uttarakhand 560001 | Phone: +91-8012345678")

        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(PAGE_WIDTH/2, top - 56,
                            "GSTIN: 29ABCDE1234F1Z5 | PAN: ABCDE1234F")

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



   #Draw UPI qr code (for payment)
    qr_data = f"upi://pay?pa=7830424458@slc&pn=MobileWorld&am={payable}&cu=INR"
    qr_img = qrcode.make(qr_data)
    qr_path = "invoices/qr_temp.png"
    qr_img.save(qr_path)


    # Upi qr code for payments
    c.setFont("Helvetica-Bold", 11)
    c.drawString(left, y, "Scan to Pay")

    c.drawImage(qr_path, left, y - 130, width=120, height=120)


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

    c.setFont("Helvetica", 7)
    c.drawCentredString(PAGE_WIDTH / 2, bottom_margin,
                        "This is a computer-generated invoice and does not require a signature")

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
async def purchase_product(product_id: int, data: PurchaseData):
    product = await Products.get(id=product_id)

    supplier = await Supplier.get_or_none(id=data.supplier_id)
    if not supplier:
        raise HTTPException(400, "Invalid supplier id")

    if data.quantity <= 0:
        raise HTTPException(400, "Quantity must be > 0")

    product.quantity_in_stock += data.quantity
    product.last_purchase_price = Decimal(str(data.buy_price))
    product.supplied_by_id = data.supplier_id
    await product.save()

    total_amount = Decimal(str(data.buy_price)) * data.quantity

    await StockMovement.create(
        product_id=product_id,
        movement_type="purchase",
        quantity=data.quantity,
        price_per_unit=Decimal(str(data.buy_price)),
        total_amount=total_amount,
        supplier_id=data.supplier_id,
    )

    timestamp = datetime.now().strftime("%d-%m-%Y %I:%M %p")

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
async def sell_products(data: SellMultiData):

    items_out = []
    updates = []
    grand_total = Decimal("0")

    invoice_number = f"INV-{int(datetime.now().timestamp())}"

    for item in data.items:
        product = await Products.get(id=item.product_id)

        if product.quantity_in_stock < item.quantity:
            raise HTTPException(400, f"Not enough stock for {product.name}")

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

        await StockMovement.create(
            product_id=product.id,
            movement_type="sale",
            quantity=qty,
            price_per_unit=price,
            total_amount=qty * price,
            customer_name=data.customer_name,
            customer_phone=data.customer_phone,
            customer_email=data.customer_email,
            invoice_number=invoice_number
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


    # SEND EMAIL 
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




##################### Download Pdf   #####################################
@app.get("/download_invoice/{invoice_number}")
async def download(invoice_number: str):
    file_path = f"invoices/{invoice_number}.pdf"
    if not os.path.exists(file_path):
        raise HTTPException(404, "Invoice not found")
    return FileResponse(file_path, filename=f"{invoice_number}.pdf")







######################### Movement History #################################
@app.get("/product/{product_id}/movements")
async def product_movements(product_id: int):
    moves = await StockMovement.filter(product_id=product_id).order_by("-timestamp")
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
            ts = m.timestamp.isoformat(sep=" ") if m.timestamp else None
        except Exception:
            try:
                ts = str(m.timestamp)
            except Exception:
                ts = None

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
async def all_movements():
    items = await StockMovement.all().order_by("-timestamp")
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
async def add_supplier(data: supplier_pydanticIn):
    obj = await Supplier.create(**data.dict(exclude_unset=True))
    return {"status": "ok", "data": await supplier_pydantic.from_tortoise_orm(obj)}

@app.get("/supplier")
async def get_suppliers():
    query = Supplier.all().order_by("id")   # correct (QuerySet)
    data = await supplier_pydantic.from_queryset(query)
    return {"status": "ok", "data": data}


@app.get("/supplier/{id}")
async def get_supplier(id: int):
    return {"status": "ok", "data": await supplier_pydantic.from_queryset_single(Supplier.get(id=id))}

@app.put("/supplier/{id}")
async def update_supplier(id: int, data: dict = Body(...)):
    supplier = await Supplier.get(id=id)

    # Apply only provided fields
    for key, value in data.items():
        if hasattr(supplier, key):
            setattr(supplier, key, value)

    await supplier.save()
    return {
        "status": "ok",
        "data": await supplier_pydantic.from_tortoise_orm(supplier)
    }

@app.delete("/supplier/{id}")
async def delete_supplier(id: int):
    await Supplier.filter(id=id).delete()
    return {"status": "ok"}



############################   Product Crud   ################################
async def add_product(supplier_id: int, data: product_pydanticIn):
    supplier = await Supplier.get(id=supplier_id)
    d = data.dict(exclude_unset=True)
    d["revenue"] = d.get("quantity_sold", 0) * d.get("unit_price", 0)
    d["net_profit"] = d.get("profit_per_piece", 0) * d.get("quantity_sold", 0)
    obj = await Products.create(**d, supplied_by=supplier)
    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(obj)}

@app.get("/product")
async def get_products():
    products = await Products.all().order_by("id").prefetch_related("supplied_by")
    data = []
    for p in products:
        item = await product_pydantic.from_tortoise_orm(p)
        d = item.dict()
        d["supplied_by_id"] = p.supplied_by_id
        data.append(d)
    return {"status": "ok", "data": data}

@app.get("/product/{id}")
async def get_product(id: int):
    return {"status": "ok", "data": await product_pydantic.from_queryset_single(Products.get(id=id))}

@app.put("/product/{id}")
async def update_product(id: int, data: product_pydanticIn):
    p = await Products.get(id=id)
    upd = data.dict(exclude_unset=True)
    for k, v in upd.items():
        setattr(p, k, v)
    p.revenue = p.quantity_sold * p.unit_price
    p.net_profit = p.profit_per_piece * p.quantity_sold
    await p.save()
    return {"status": "ok", "data": await product_pydantic.from_tortoise_orm(p)}

@app.delete("/product/{id}")
async def delete_product(id: int):
    await Products.filter(id=id).delete()
    return {"status": "ok"}



#######################   Database Init   ###########################
DB_URL = os.getenv("DB_URL")

if not DB_URL:
    raise Exception("❌ DB_URL missing in .env (PostgreSQL connection required)")

register_tortoise(
    app,                              # FastAPI ka  instance jha ORM hook hoga
    db_url=DB_URL,                    # Database ki connection string
    modules={"models": ["models"]},   # Tortoise ko batata hai ki models kahan hain
    generate_schemas=True,            # Automatically tables create kar dega
    add_exception_handlers=True,      # Database mai errors ko readable banayega
)




#-----------OTP API for mobile----------

STATIC_OTP = "123456"


verified_numbers = set()
users = []


class OTPRequest(BaseModel):
    mobile: str


class OTPVerifyRequest(BaseModel):
    mobile: str
    otp: str


class RegisterRequest(BaseModel):
    name: str
    mobile: str
    password: str


@app.post("/send-otp")
def send_otp(data: OTPRequest):
    return {
        "message": "OTP sent successfully",
        "otp_for_testing": STATIC_OTP  # ✅ ONLY FOR LEARNING
    }


@app.post("/verify-otp")
def verify_otp(data: OTPVerifyRequest):
    if data.otp == STATIC_OTP:
        verified_numbers.add(data.mobile)
        return {"verified": True}
    else:
        return {"verified": False}


@app.post("/register")
def register_user(data: RegisterRequest):

    # ✅ Check if mobile is verified
    if data.mobile not in verified_numbers:
        raise HTTPException(status_code=400, detail="Mobile number not verified")

    user = {
        "name": data.name,
        "mobile": data.mobile,
        "password": data.password
    }

    users.append(user)

    return {
        "message": "✅ User registered successfully",
        "user": user
    }


#-----------OTP API for mail-------------------

email_otp_store = {}


from random import randint

@app.post("/send-email-otp")
async def send_email_otp(email: str):
    if not MAIL_CONF:
        raise HTTPException(500, "Email server not configured")

    otp = randint(100000, 999999)
    email_otp_store[email] = otp

    fm = FastMail(MAIL_CONF)

    html = f"""
    <h3>Your Email Verification OTP</h3>
    <p>Your OTP is: <strong>{otp}</strong></p>
    <p>This OTP will expire in 5 minutes.</p>
    """

    message = MessageSchema(
        subject="Email OTP Verification",
        recipients=[email],
        body=html,
        subtype="html"
    )

    try:
        await fm.send_message(message)
    except Exception as e:
        print("Email error:", e)
        raise HTTPException(500, "Failed to send OTP email")

    return {"status": "ok", "message": "OTP sent to email"}



@app.post("/verify-email-otp")
async def verify_email_otp(email: str, otp: int):
    real_otp = email_otp_store.get(email)

    if not real_otp:
        raise HTTPException(400, "OTP expired or not found")

    if real_otp != otp:
        raise HTTPException(400, "Invalid OTP")

    # OTP is correct — remove it
    del email_otp_store[email]

    return {"status": "ok", "verified": True}
