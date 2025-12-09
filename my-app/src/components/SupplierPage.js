import React, { useEffect, useState } from "react";
import secureFetch from "../secureFetch";

const SupplierPage = () => {
  const [suppliers, setSuppliers] = useState([]);
  const [form, setForm] = useState({
    name: "",
    company: "",
    email: "",
    phone: "",
  });

  const [edit, setEdit] = useState(null);

  const loadSuppliers = async () => {
    const res = await secureFetch("http://127.0.0.1:8000/supplier");
    const data = await res.json();
    setSuppliers(data.data || []);
  };

  useEffect(() => {
    loadSuppliers();
  }, []);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const addSupplier = async (e) => {
    e.preventDefault();
    const res = await secureFetch("http://127.0.0.1:8000/supplier", {
      method: "POST",
      body: JSON.stringify(form),
    });

    if (res.ok) {
      alert("Supplier added");
      setForm({ name: "", company: "", email: "", phone: "" });
      loadSuppliers();
    }
  };

  const updateSupplier = async (e) => {
    e.preventDefault();
    const res = await secureFetch(`http://127.0.0.1:8000/supplier/${edit.id}`, {
      method: "PUT",
      body: JSON.stringify(edit),
    });

    if (res.ok) {
      alert("Supplier updated");
      setEdit(null);
      loadSuppliers();
    }
  };

  const deleteSupplier = async (id) => {
    if (!window.confirm("Delete this supplier?")) return;

    const res = await secureFetch(`http://127.0.0.1:8000/supplier/${id}`, {
      method: "DELETE",
    });

    if (res.ok) {
      alert("Supplier deleted");
      loadSuppliers();
    }
  };

  return (
    <div className="container mt-4">

      <h2 className="mb-3">Suppliers</h2>

      {/* ADD FORM */}
      <div className="card shadow-sm mb-4">
        <div className="card-body">
          <h4>Add Supplier</h4>

          <form onSubmit={addSupplier}>
            <div className="row">
              <div className="col-md-6 mb-3">
                <label>Name</label>
                <input className="form-control" name="name" value={form.name} onChange={handleChange} required/>
              </div>

              <div className="col-md-6 mb-3">
                <label>Company</label>
                <input className="form-control" name="company" value={form.company} onChange={handleChange} required/>
              </div>

              <div className="col-md-6 mb-3">
                <label>Email</label>
                <input className="form-control" name="email" value={form.email} onChange={handleChange} required/>
              </div>

              <div className="col-md-6 mb-3">
                <label>Phone</label>
                <input className="form-control" name="phone" value={form.phone} onChange={handleChange} required/>
              </div>
            </div>

            <button className="btn btn-primary w-100">Add Supplier</button>
          </form>
        </div>
      </div>

      {/* SUPPLIER TABLE */}
      <div className="table-responsive shadow-sm">
        <table className="table table-bordered table-hover text-center">
          <thead className="table-primary">
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Company</th>
              <th>Email</th>
              <th>Phone</th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            {suppliers.length > 0 ? (
              suppliers.map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td>{s.name}</td>
                  <td>{s.company}</td>
                  <td>{s.email}</td>
                  <td>{s.phone}</td>
                  <td>
                    <button className="btn btn-warning btn-sm me-2"
                      onClick={() => setEdit({ ...s })}
                    >
                      Edit
                    </button>

                    <button className="btn btn-danger btn-sm"
                      onClick={() => deleteSupplier(s.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))
            ) : (
              <tr><td colSpan="6">No suppliers found</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* EDIT FORM */}
      {edit && (
        <div className="card shadow-sm mt-4">
          <div className="card-body">
            <h4>Edit Supplier</h4>

            <form onSubmit={updateSupplier}>
              <div className="mb-3">
                <label>Name</label>
                <input className="form-control" value={edit.name}
                  onChange={(e) => setEdit({ ...edit, name: e.target.value })}/>
              </div>

              <div className="mb-3">
                <label>Company</label>
                <input className="form-control" value={edit.company}
                  onChange={(e) => setEdit({ ...edit, company: e.target.value })}/>
              </div>

              <div className="mb-3">
                <label>Email</label>
                <input className="form-control" value={edit.email}
                  onChange={(e) => setEdit({ ...edit, email: e.target.value })}/>
              </div>

              <div className="mb-3">
                <label>Phone</label>
                <input className="form-control" value={edit.phone}
                  onChange={(e) => setEdit({ ...edit, phone: e.target.value })}/>
              </div>

              <button className="btn btn-success w-100">Update</button>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};

export default SupplierPage;
