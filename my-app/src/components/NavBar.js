import React, { useContext, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ProductContext } from "../ProductContext";

const NavBar = () => {
  const [products] = useContext(ProductContext);
  const [user, setUser] = useState(null);

  const fetchUser = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;

    try {
      const res = await fetch("http://127.0.0.1:8000/users/me", {
        headers: {
          Authorization: "Bearer " + token,
        },
      });

      if (res.status === 401) {
        localStorage.removeItem("token");
        window.location.href = "/login";
        return;
      }

      const data = await res.json();
      setUser(data);
    } catch (err) {}
  };

  useEffect(() => {
    fetchUser();
  }, []);

  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-primary px-3">
      <div className="d-flex align-items-center gap-3">
        <Link to="/" className="navbar-brand fw-bold">Home</Link>
        <Link to="/addproduct" className="nav-link text-white">Add Product</Link>
        <Link to="/purchase" className="nav-link text-white">Purchase Product</Link>
        <Link to="/sell" className="nav-link text-white">Sell Product</Link>
        <Link to="/suppliers" className="nav-link text-white">Suppliers</Link>
        <Link to="/movement/1" className="nav-link text-white">Movement</Link>
      </div>

      <div className="ms-auto d-flex align-items-center gap-3 text-white">
        <span>Products: {products.data.length}</span>
        {user && <span>👤 {user.username}</span>}

        <button
          className="btn btn-light btn-sm"
          onClick={() => {
            localStorage.removeItem("token");
            window.location.href = "/login";
          }}
        >
          Logout
        </button>
      </div>
    </nav>
  );
};

export default NavBar;
