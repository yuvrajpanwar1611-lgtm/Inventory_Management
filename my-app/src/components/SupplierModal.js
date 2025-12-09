// src/components/SupplierModal.js
import React from "react";

const SupplierModal = ({ open, loading, supplier, onClose }) => {
  if (!open) return null;

  return (
    <>
      {/* BACKDROP */}
      <div className="modal-backdrop fade show"></div>

      {/* MODAL */}
      <div
        className="modal fade show"
        style={{ display: "block" }}
        tabIndex="-1"
        onClick={onClose}
      >
        <div
          className="modal-dialog modal-dialog-centered modal-lg"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="modal-content shadow">

            <div className="modal-header bg-primary text-white">
              <h5 className="modal-title">Supplier Details</h5>
              <button className="btn-close btn-close-white" onClick={onClose}></button>
            </div>

            <div className="modal-body">
              {loading ? (
                <div className="text-center py-4">
                  <div className="spinner-border text-primary"></div>
                </div>
              ) : (
                supplier && (
                  <>
                    <p><strong>Name:</strong> {supplier.name}</p>
                    <p><strong>Company:</strong> {supplier.company}</p>
                    <p><strong>Email:</strong> {supplier.email}</p>
                    <p><strong>Phone:</strong> {supplier.phone}</p>

                    <div className="d-flex gap-2 mt-3">
                      {supplier.email && (
                        <a className="btn btn-primary" href={`mailto:${supplier.email}`}>
                          Email
                        </a>
                      )}
                      {supplier.phone && (
                        <a className="btn btn-success" href={`tel:${supplier.phone}`}>
                          Call
                        </a>
                      )}
                    </div>
                  </>
                )
              )}
            </div>

            {/* <div className="modal-footer">
              <button className="btn btn-secondary" onClick={onClose}>Close</button>
            </div> */}

          </div>
        </div>
      </div>
    </>
  );
};

export default SupplierModal;
