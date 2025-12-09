import React, { useState, useEffect } from "react";

const AddProducts = () => {
  const [info, setInfo] = useState({
    Supplier: "",
    ProductName: "",
    UnitPrice: "",
    ProfitPerPiece: "",
  });

  // Redirect to login if token missing
  useEffect(() => {
    if (!localStorage.getItem("token")) {
      window.location.href = "/login";
    }
  }, []);

  const handleChange = (e) => {
    setInfo({ ...info, [e.target.name]: e.target.value });
  };

  const postData = async (e) => {
    e.preventDefault();

    const payload = {
      name: info.ProductName,
      quantity_in_stock: 0,
      quantity_sold: 0,
      unit_price: Number(info.UnitPrice),
      revenue: 0,
      profit_per_piece: Number(info.ProfitPerPiece),
    };

    const token = localStorage.getItem("token");

    const res = await fetch(`http://127.0.0.1:8000/product/${info.Supplier}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      body: JSON.stringify(payload),
    });

    // If token expired → redirect to login
    if (res.status === 401) {
      alert("Session expired. Please login again.");
      localStorage.removeItem("token");
      window.location.href = "/login";
      return;
    }

    if (res.ok) {
      alert("Product added!");
      setInfo({
        Supplier: "",
        ProductName: "",
        UnitPrice: "",
        ProfitPerPiece: "",
      });
    } else {
      const error = await res.json();
      alert(error.detail || "Failed to add product");
    }
  };

  return (
    <div className="container mt-4">
      <div className="card shadow-sm">
        <div className="card-body">
          <h3 className="card-title mb-3">Add Product</h3>

          <form onSubmit={postData}>
            {/* Supplier ID FIRST */}
            <div className="mb-3">
              <label className="form-label">Supplier ID</label>
              <input
                className="form-control"
                name="Supplier"
                value={info.Supplier}
                onChange={handleChange}
                required
              />
            </div>

            {/* Product Name */}
            <div className="mb-3">
              <label className="form-label">Product Name</label>
              <input
                className="form-control"
                name="ProductName"
                value={info.ProductName}
                onChange={handleChange}
                required
              />
            </div>

            {/* Unit Price */}
            <div className="mb-3">
              <label className="form-label">Unit Price</label>
              <input
                className="form-control"
                type="number"
                name="UnitPrice"
                value={info.UnitPrice}
                onChange={handleChange}
                required
              />
            </div>

            {/* Profit Per Piece */}
            <div className="mb-3">
              <label className="form-label">Profit Per Piece</label>
              <input
                className="form-control"
                type="number"
                name="ProfitPerPiece"
                value={info.ProfitPerPiece}
                onChange={handleChange}
                required
              />
            </div>

            <button className="btn btn-primary w-100">Add Product</button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AddProducts;
