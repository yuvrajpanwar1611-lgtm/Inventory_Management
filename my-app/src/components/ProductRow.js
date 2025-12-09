// src/components/ProductRow.js
import React from "react";

const ProductRow = ({ product, onEdit, onDelete, onViewSupplier }) => {
  return (
    <tr>
      <td>{product.id}</td>
      <td>{product.name}</td>
      <td>{product.quantity_in_stock}</td>
      <td>{product.quantity_sold}</td>
      <td>₹{product.unit_price}</td>
      <td>₹{product.revenue}</td>

      <td className={Number(product.net_profit) > 0 ? "text-success fw-bold" : ""}>
        ₹{product.net_profit}
      </td>

      <td>
        <button
          className="btn btn-info btn-sm me-2"
          onClick={() => onViewSupplier(product.supplied_by_id)}
        >
          Supplier
        </button>

        <button
          className="btn btn-warning btn-sm me-2"
          onClick={() => onEdit(product)}
        >
          Edit
        </button>

        <button
          className="btn btn-danger btn-sm"
          onClick={() => onDelete(product)}
        >
          Delete
        </button>
      </td>
    </tr>
  );
};

export default ProductRow;
