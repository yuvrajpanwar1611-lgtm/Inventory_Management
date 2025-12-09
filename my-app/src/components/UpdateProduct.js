import React, { useContext, useEffect } from "react";
import { UpdateProductContext } from "../UpdateProductContext";
import secureFetch from "../secureFetch";

const UpdateProduct = () => {
  const [info, setInfo] = useContext(UpdateProductContext);

  useEffect(() => {
    if (!info.ProductId) {
      window.location.href = "/";
    }
  }, []);

  const handleChange = (e) => {
    setInfo({ ...info, [e.target.name]: e.target.value });
  };

  const updateData = async (e) => {
    e.preventDefault();

    const payload = {
      name: info.ProductName,
      quantity_in_stock: Number(info.QuantityInStock),
      quantity_sold: Number(info.QuantitySold),
      unit_price: Number(info.UnitPrice),
      revenue: Number(info.Revenue),
      profit_per_piece: Number(info.ProfitPerPiece),
    };

    const res = await secureFetch(
      `http://127.0.0.1:8000/product/${info.ProductId}`,
      {
        method: "PUT",
        body: JSON.stringify(payload),
      }
    );

    if (res.ok) {
      alert("Product updated successfully!");
    } else {
      alert("Update failed");
    }
  };

  return (
    <div className="container mt-4">
      <div className="card shadow-sm">
        <div className="card-body">
          <h3 className="card-title mb-3">Update Product</h3>

          <form onSubmit={updateData}>
            <div className="mb-3">
              <label>Product Name</label>
              <input
                className="form-control"
                name="ProductName"
                value={info.ProductName}
                onChange={handleChange}
              />
            </div>

            <div className="row">
              <div className="col-md-6 mb-3">
                <label>Quantity In Stock</label>
                <input
                  type="number"
                  className="form-control"
                  name="QuantityInStock"
                  value={info.QuantityInStock}
                  onChange={handleChange}
                />
              </div>

              <div className="col-md-6 mb-3">
                <label>Quantity Sold</label>
                <input
                  type="number"
                  className="form-control"
                  name="QuantitySold"
                  value={info.QuantitySold}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="row">
              <div className="col-md-6 mb-3">
                <label>Unit Price</label>
                <input
                  type="number"
                  className="form-control"
                  name="UnitPrice"
                  value={info.UnitPrice}
                  onChange={handleChange}
                />
              </div>

              <div className="col-md-6 mb-3">
                <label>Revenue</label>
                <input
                  type="number"
                  className="form-control"
                  name="Revenue"
                  value={info.Revenue}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="mb-3">
              <label>Profit Per Piece</label>
              <input
                type="number"
                className="form-control"
                name="ProfitPerPiece"
                value={info.ProfitPerPiece}
                onChange={handleChange}
              />
            </div>

            <button className="btn btn-success w-100">Update Product</button>
          </form>

        </div>
      </div>
    </div>
  );
};

export default UpdateProduct;
