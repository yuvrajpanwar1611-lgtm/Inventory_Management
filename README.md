# Inventory Management Backend (FastAPI)

A FastAPI-based inventory management system with user authentication, product management, supplier tracking, and invoice generation.

## Features

- User authentication with JWT tokens
- Email and Phone OTP verification
- Product CRUD operations
- Supplier management
- Stock purchase and sales tracking
- Invoice PDF generation
- Stock movement history
- Multi-user support with data isolation

## Setup

### Prerequisites

- Python 3.8+
- PostgreSQL database
- Gmail account (for email OTPs - optional)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the root directory:
   ```env
   DB_URL=postgres://user:password@localhost:5432/inventory_db
   SECRET_KEY=your-secret-key-here
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   ```

4. Run the application:
   ```bash
   uvicorn app:app --reload
   ```

## API Endpoints

- `/token` - Login (OAuth2)
- `/signup` - User registration (requires email/phone OTP)
- `/register` - Mobile-only registration
- `/send-email-otp` - Send email OTP
- `/verify-email-otp` - Verify email OTP
- `/send-otp` - Send phone OTP
- `/verify-otp` - Verify phone OTP
- `/product` - Product CRUD
- `/supplier` - Supplier CRUD
- `/product/purchase/{id}` - Purchase stock
- `/product/sell` - Sell products (generates invoice)
- `/download_invoice/{invoice_number}` - Download invoice PDF
- `/movements` - View all stock movements

## Recent Fixes

- ✅ Added missing `/download_invoice/{invoice_number}` endpoint
- ✅ Improved OTP system with rate limiting and better error handling
- ✅ Added email verification requirement for signup
- ✅ Better error handling for missing environment variables
- ✅ Improved security and validation

## Notes

- SECRET_KEY is required for production. If not set, a temporary key is generated (NOT SECURE).
- Email configuration is optional but required for sending OTPs and invoices.
- Database migrations should be run separately (generate_schemas=False).