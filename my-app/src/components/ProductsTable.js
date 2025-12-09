// src/components/ProductsTable.js
import React, { useEffect, useContext, useState } from "react";
import { ProductContext } from "../ProductContext";
import { UpdateProductContext } from "../UpdateProductContext";
import ProductRow from "./ProductRow";
import SupplierModal from "./SupplierModal";
import { useNavigate } from "react-router-dom";

const ProductsTable = () => {
  const [products, setProducts] = useContext(ProductContext);
  const [updateProductInfo, setUpdateProductInfo] = useContext(UpdateProductContext);

  const [supplierModalOpen, setSupplierModalOpen] = useState(false);
  const [supplierLoading, setSupplierLoading] = useState(false);
  const [supplierData, setSupplierData] = useState(null);

  const navigate = useNavigate();

  // secure fetch helper
  const secureFetch = async (url, options = {}) => {
    const token = localStorage.getItem("token");

    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    if (token) headers.Authorization = "Bearer " + token;

    const res = await fetch(url, { ...options, headers });

    if (res.status === 401) {
      alert("Session expired. Please login again.");
      localStorage.removeItem("token");
      window.location.href = "/login";
    }

    return res;
  };

  const fetchProducts = async () => {
    const res = await secureFetch("http://127.0.0.1:8000/product");
    const data = await res.json();
    setProducts({ data: data.data || [] });
  };

  useEffect(() => {
    fetchProducts();
  }, []);

  const handleEdit = (p) => {
    setUpdateProductInfo({
      ProductId: p.id,
      ProductName: p.name,
      QuantityInStock: p.quantity_in_stock,
      QuantitySold: p.quantity_sold,
      UnitPrice: p.unit_price,
      Revenue: p.revenue,
      ProfitPerPiece: p.profit_per_piece,
    });
    navigate("/updateproduct");
  };

  const handleDelete = async (p) => {
    if (!window.confirm("Delete this product?")) return;

    const res = await secureFetch(`http://127.0.0.1:8000/product/${p.id}`, {
      method: "DELETE",
    });

    if (res.ok) {
      setProducts(prev => ({
        data: prev.data.filter(x => x.id !== p.id)
      }));
      alert("Product deleted");
    }
  };

  // NEW: open supplier modal
  const handleViewSupplier = async (supplierId) => {
    if (!supplierId) {
      alert("No supplier linked to this product.");
      return;
    }

    setSupplierLoading(true);
    setSupplierModalOpen(true);

    try {
      const res = await secureFetch(`http://127.0.0.1:8000/supplier/${supplierId}`);
      const json = await res.json();

      // FIX: now always gives clean supplier object
      const supplierObject = json.data ?? json ?? null;
      setSupplierData(supplierObject);

    } catch (err) {
      console.error(err);
      alert("Failed to load supplier details");
      setSupplierModalOpen(false);
    }

    setSupplierLoading(false);
  };

  return (
    <div className="container mt-4">
      <h2 className="mb-3 fw-bold">Products</h2>

      <div className="table-responsive">
        <table className="table table-bordered table-hover text-center align-middle shadow">
          <thead className="table-primary">
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>In Stock</th>
              <th>Sold</th>
              <th>Unit Price</th>
              <th>Revenue</th>
              <th>Net Profit</th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            {products.data?.length > 0 ? (
              products.data.map((p) => (
                <ProductRow
                  key={p.id}
                  product={p}
                  onEdit={handleEdit}
                  onDelete={handleDelete}
                  onViewSupplier={handleViewSupplier}
                />
              ))
            ) : (
              <tr>
                <td colSpan="8" className="fw-bold py-3">No Products Found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* MODAL */}
      <SupplierModal
        open={supplierModalOpen}
        loading={supplierLoading}
        supplier={supplierData}
        onClose={() => setSupplierModalOpen(false)}
      />
    </div>
  );
};

export default ProductsTable;
