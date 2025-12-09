import React, { useState, useEffect } from "react";
import secureFetch from "../secureFetch";

const PurchaseProduct = () => {
  const [products, setProducts] = useState([]);
  const [suppliers, setSuppliers] = useState([]);

  const [form, setForm] = useState({
    productId: "",
    supplier_id: "",
    quantity: "",
    buy_price: "",
  });

  const [selectedProduct, setSelectedProduct] = useState(null);

  const loadData = async () => {
    const prod = await secureFetch("http://127.0.0.1:8000/product");
    const prodData = await prod.json();

    const sup = await secureFetch("http://127.0.0.1:8000/supplier");
    const supData = await sup.json();

    setProducts(prodData.data || []);
    setSuppliers(supData.data || []);
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleProductSelect = (e) => {
    const pid = Number(e.target.value);
    const product = products.find((p) => p.id === pid);

    setSelectedProduct(product);

    setForm({
      ...form,
      productId: pid,
      supplier_id: product ? product.supplied_by_id : "",
      buy_price: product ? Number(product.unit_price) : "",
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const payload = {
      supplier_id: Number(form.supplier_id),
      quantity: Number(form.quantity),
      buy_price: Number(form.buy_price),
    };

    const res = await secureFetch(
      `http://127.0.0.1:8000/product/purchase/${form.productId}`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );

    const data = await res.json();

    if (!res.ok) {
      alert(data.detail || "Purchase failed");
      return;
    }

    alert("Stock purchased successfully!");
    setForm({ productId: "", supplier_id: "", quantity: "", buy_price: "" });
    setSelectedProduct(null);
  };

  return (
    <div className="container mt-4">
      <div className="card shadow-sm">
        <div className="card-body">

          <h3 className="mb-3">Purchase Product</h3>

          <form onSubmit={handleSubmit}>

            {/* Product dropdown */}
            <div className="mb-3">
              <label>Select Product</label>
              <select
                className="form-control"
                value={form.productId}
                onChange={handleProductSelect}
              >
                <option value="">-- Select Product --</option>
                {products.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Supplier dropdown auto-filled */}
            <div className="mb-3">
              <label>Select Supplier</label>
              <select
                className="form-control"
                value={form.supplier_id}
                onChange={(e) =>
                  setForm({ ...form, supplier_id: e.target.value })
                }
              >
                <option value="">-- Select Supplier --</option>
                {suppliers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.company})
                  </option>
                ))}
              </select>
            </div>

            {/* Quantity + Price */}
            <div className="row">
              <div className="col-md-6 mb-3">
                <label>Quantity</label>
                <input
                  type="number"
                  className="form-control"
                  value={form.quantity}
                  onChange={(e) =>
                    setForm({ ...form, quantity: e.target.value })
                  }
                  required
                />
              </div>

              <div className="col-md-6 mb-3">
                <label>Buy Price</label>
                <input
                  type="number"
                  className="form-control"
                  value={form.buy_price}
                  onChange={(e) =>
                    setForm({ ...form, buy_price: e.target.value })
                  }
                  required
                />
              </div>
            </div>

            <button className="btn btn-primary w-100">Purchase</button>

          </form>
        </div>
      </div>
    </div>
  );
};

export default PurchaseProduct;
