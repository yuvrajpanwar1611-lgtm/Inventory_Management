import React from "react";
import { BrowserRouter as Router, Routes, Route, useLocation } from "react-router-dom";

import NavBar from "./components/NavBar";
import ProductsTable from "./components/ProductsTable";
import AddProducts from "./components/AddProducts";
import UpdateProduct from "./components/UpdateProduct";
import SupplierPage from "./components/SupplierPage";
import PurchaseProduct from "./components/PurchaseProduct";
import SellProduct from "./components/SellProduct";
import StockMovement from "./components/StockMovement";
import ChatBot from "./components/ChatBot";

import Login from "./Login";
import Signup from "./Signup";
import ProtectedRoute from "./ProtectedRoute";

import { ProductProvider } from "./ProductContext";
import { SupplierContextProvider } from "./SupplierContext";
import { UpdateProductContextProvider } from "./UpdateProductContext";

function Layout() {
  const location = useLocation();
  const isLoggedIn = Boolean(localStorage.getItem("token"));

  // ❌ Hide NavBar & ChatBot on Login + Signup pages
  const hideUI =
    location.pathname === "/login" || location.pathname === "/signup";

  return (
    <>
      {/* NAVBAR → Show only when logged in */}
      {!hideUI && isLoggedIn && <NavBar />}

      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <ProductsTable />
            </ProtectedRoute>
          }
        />

        <Route
          path="/addproduct"
          element={
            <ProtectedRoute>
              <AddProducts />
            </ProtectedRoute>
          }
        />

        <Route
          path="/updateproduct"
          element={
            <ProtectedRoute>
              <UpdateProduct />
            </ProtectedRoute>
          }
        />

        <Route
          path="/purchase"
          element={
            <ProtectedRoute>
              <PurchaseProduct />
            </ProtectedRoute>
          }
        />

        <Route
          path="/sell"
          element={
            <ProtectedRoute>
              <SellProduct />
            </ProtectedRoute>
          }
        />

        <Route
          path="/suppliers"
          element={
            <ProtectedRoute>
              <SupplierPage />
            </ProtectedRoute>
          }
        />

        <Route
          path="/movement/:id"
          element={
            <ProtectedRoute>
              <StockMovement />
            </ProtectedRoute>
          }
        />
      </Routes>

      {/* CHATBOT → Show only when logged in AND not on login/signup */}
      {!hideUI && isLoggedIn && <ChatBot />}
    </>
  );
}

function App() {
  return (
    <ProductProvider>
      <SupplierContextProvider>
        <UpdateProductContextProvider>
          <Router>
            <Layout />
          </Router>
        </UpdateProductContextProvider>
      </SupplierContextProvider>
    </ProductProvider>
  );
}

export default App;
