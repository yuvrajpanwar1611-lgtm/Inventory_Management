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




from tortoise import fields, models
from tortoise.contrib.pydantic import pydantic_model_creator
from decimal import Decimal


class User(models.Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=40, unique=True, index=True)
    email = fields.CharField(max_length=120, unique=True, index=True)
    phone = fields.CharField(max_length=20, unique=True)

    full_name = fields.CharField(max_length=120, null=True)
    hashed_password = fields.CharField(max_length=255)

    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "users"


class Supplier(models.Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=60)
    company = fields.CharField(max_length=80)
    email = fields.CharField(max_length=120)
    phone = fields.CharField(max_length=20)

    user = fields.ForeignKeyField("models.User", related_name="suppliers")

    class Meta:
        table = "supplier"
        unique_together = (("user_id", "email"), ("user_id", "phone"))
        indexes = [("user_id",)]


class Products(models.Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=100)

    quantity_in_stock = fields.IntField(default=0)
    quantity_sold = fields.IntField(default=0)

    unit_price = fields.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))
    revenue = fields.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0.00"))

    profit_per_piece = fields.DecimalField(max_digits=10, decimal_places=2, default=Decimal("0.00"))
    net_profit = fields.DecimalField(max_digits=20, decimal_places=2, default=Decimal("0.00"))

    last_purchase_price = fields.DecimalField(max_digits=12, decimal_places=2, default=Decimal("0.00"))

    supplied_by = fields.ForeignKeyField("models.Supplier", related_name="goods_supplied", null=True)
    user = fields.ForeignKeyField("models.User", related_name="products")

    class Meta:
        table = "products"


class StockMovement(models.Model):
    id = fields.IntField(pk=True)

    product = fields.ForeignKeyField("models.Products", related_name="movements")
    movement_type = fields.CharField(max_length=20)

    quantity = fields.IntField()
    price_per_unit = fields.DecimalField(max_digits=12, decimal_places=2)
    total_amount = fields.DecimalField(max_digits=18, decimal_places=2)

    supplier = fields.ForeignKeyField("models.Supplier", related_name="movements", null=True)

    customer_name = fields.CharField(max_length=200, null=True)
    customer_phone = fields.CharField(max_length=50, null=True)
    customer_email = fields.CharField(max_length=200, null=True)

    invoice_number = fields.CharField(max_length=120, null=True)
    timestamp = fields.DatetimeField(auto_now_add=True)

    user = fields.ForeignKeyField("models.User", related_name="movements")

    class Meta:
        table = "stock_movement"


# Pydantic outputs
User_Pydantic = pydantic_model_creator(User, name="UserOut")
product_pydantic = pydantic_model_creator(Products, name="Product")
product_pydanticIn = pydantic_model_creator(Products, name="ProductIn", exclude_readonly=True)
supplier_pydantic = pydantic_model_creator(Supplier, name="Supplier")
supplier_pydanticIn = pydantic_model_creator(Supplier, name="SupplierIn", exclude_readonly=True)
stockmovement_pydantic = pydantic_model_creator(StockMovement, name="StockMovement")

