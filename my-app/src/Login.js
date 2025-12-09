import React, { useState } from "react";

const Login = () => {
  const [form, setForm] = useState({ username: "", password: "" });

  const handleLogin = async (e) => {
    e.preventDefault();

    const body = new URLSearchParams();
    body.append("username", form.username);
    body.append("password", form.password);

    const res = await fetch("http://127.0.0.1:8000/token", {
      method: "POST",
      body,
    });

    const data = await res.json();

    if (!res.ok) {
      return alert(data.detail || "Login failed");
    }

    localStorage.setItem("token", data.access_token);
    window.location.href = "/";
  };

  return (
    <div className="container mt-5" style={{ maxWidth: "450px" }}>
      <div className="card shadow-sm p-4">
        <h3 className="text-center mb-3">Login</h3>

        <form onSubmit={handleLogin}>
          <input className="form-control mb-3" placeholder="Username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
          />

          <input className="form-control mb-3" type="password" placeholder="Password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />

          <button className="btn btn-primary w-100">Login</button>
        </form>

        <div className="text-center mt-3">
          <a href="/signup">Create new account</a>
        </div>
      </div>
    </div>
  );
};

export default Login;
