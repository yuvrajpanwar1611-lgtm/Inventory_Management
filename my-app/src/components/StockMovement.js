import React, { useEffect, useState } from "react";
import secureFetch from "../secureFetch";

const StockMovement = () => {
  const [movements, setMovements] = useState([]);
  const [filteredMovements, setFilteredMovements] = useState([]);
  const [products, setProducts] = useState([]);
  const [selectedProduct, setSelectedProduct] = useState("");

  // Load all movements
  const loadMovements = async () => {
    const res = await secureFetch("http://127.0.0.1:8000/movements");
    const data = await res.json();
    setMovements(data.data || []);
    setFilteredMovements(data.data || []);
  };

  // Load product list for filter
  const loadProducts = async () => {
    const res = await secureFetch("http://127.0.0.1:8000/product");
    const data = await res.json();
    setProducts(data.data || []);
  };

  useEffect(() => {
    loadMovements();
    loadProducts();
  }, []);

  // Filter movements by selected product
  const handleFilter = (productId) => {
    setSelectedProduct(productId);

    if (productId === "") {
      setFilteredMovements(movements);
    } else {
      setFilteredMovements(
        movements.filter((m) => String(m.product_id) === String(productId))
      );
    }
  };

  return (
    <div className="container mt-4">
      <h2 className="mb-3">Stock Movement —</h2>

      {/* FILTER DROPDOWN */}
      <div className="card shadow-sm mb-4 p-3">
        <label className="form-label fw-bold">Filter by Product</label>
        <select
          className="form-control"
          value={selectedProduct}
          onChange={(e) => handleFilter(e.target.value)}
        >
          <option value="">All Products</option>
          {products.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {/* MOVEMENTS LIST */}
      {filteredMovements.length === 0 ? (
        <div className="alert alert-info">No movement history found.</div>
      ) : (
        filteredMovements.map((m) => (
          <div
            key={m.id}
            className="card shadow-sm mb-3 p-3"
            style={{
              borderLeft:
                m.movement_type === "sale"
                  ? "5px solid #e63946"
                  : "5px solid #2a9d8f",
            }}
          >
            <div className="d-flex justify-content-between">
              <h5>
                {m.movement_type === "purchase" ? (
                  <span className="badge bg-success">Purchased</span>
                ) : (
                  <span className="badge bg-danger">Sold</span>
                )}
              </h5>

              <small className="text-muted">
                {new Date(m.timestamp).toLocaleString()}
              </small>
            </div>

            <div className="mt-2">
              <p>
                <strong>Product:</strong> {m.product_name}
              </p>
              <p>
                <strong>Quantity:</strong> {m.quantity}
              </p>
              <p>
                <strong>Price Per Unit:</strong> ₹{m.price_per_unit}
              </p>
              <p>
                <strong>Total Amount:</strong> ₹{m.total_amount}
              </p>

              {m.movement_type === "purchase" && (
                <p className="text-primary">
                  <strong>Supplier ID:</strong> {m.supplier_id}
                </p>
              )}

              {m.movement_type === "sale" && (
                <>
                  <p>
                    <strong>Customer:</strong> {m.customer_name}
                  </p>
                  <p>
                    <strong>Phone:</strong> {m.customer_phone}
                  </p>
                  <p>
                    <strong>Email:</strong> {m.customer_email}
                  </p>

                  {/* DOWNLOAD INVOICE BUTTON */}
                  {m.invoice_number && (
                    <a
                      href={`http://127.0.0.1:8000/download_invoice/${m.invoice_number}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn btn-primary btn-sm mt-2"
                    >
                      Download Invoice
                    </a>
                  )}
                </>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default StockMovement;
