import React, { useState } from "react";

const Signup = () => {
  const [form, setForm] = useState({
    username: "",
    email: "",
    phone: "",
    full_name: "",
    password: "",
  });

  const [emailOtp, setEmailOtp] = useState("");
  const [emailOtpSent, setEmailOtpSent] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);

  const [phoneOtp, setPhoneOtp] = useState("");
  const [phoneOtpSent, setPhoneOtpSent] = useState(false);
  const [phoneVerified, setPhoneVerified] = useState(false);

  const [loading, setLoading] = useState(false);

  // ----------------------------------------------------
  // SEND EMAIL OTP
  // ----------------------------------------------------
  const sendEmailOtp = async () => {
    if (!form.email) return alert("Enter email");

    const res = await fetch("http://127.0.0.1:8000/send-email-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.email }),
    });

    const data = await res.json();
    alert(`Email OTP Sent: ${data.otp_for_testing}`);
    setEmailOtpSent(true);
  };

  // ----------------------------------------------------
  // VERIFY EMAIL OTP
  // ----------------------------------------------------
  const verifyEmailOtp = async () => {
    const res = await fetch("http://127.0.0.1:8000/verify-email-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: form.email, otp: emailOtp }),
    });

    const data = await res.json();
    if (data.verified) {
      setEmailVerified(true);
      alert("Email Verified");
    } else alert("Invalid OTP");
  };

  // ----------------------------------------------------
  // SEND PHONE OTP
  // ----------------------------------------------------
  const sendPhoneOtp = async () => {
    if (!form.phone) return alert("Enter phone");

    const res = await fetch("http://127.0.0.1:8000/send-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mobile: form.phone }),
    });

    const data = await res.json();
    alert(`Phone OTP Sent: ${data.otp_for_testing}`);
    setPhoneOtpSent(true);
  };

  // ----------------------------------------------------
  // VERIFY PHONE OTP
  // ----------------------------------------------------
  const verifyPhoneOtp = async () => {
    const res = await fetch("http://127.0.0.1:8000/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mobile: form.phone, otp: phoneOtp }),
    });

    const data = await res.json();
    if (data.verified) {
      setPhoneVerified(true);
      alert("Phone Verified");
    } else alert("Invalid OTP");
  };

  // ----------------------------------------------------
  // SUBMIT FORM
  // ----------------------------------------------------
  const submit = async (e) => {
    e.preventDefault();
    if (!emailVerified) return alert("Verify email first");
    if (!phoneVerified) return alert("Verify phone first");

    setLoading(true);
    const res = await fetch("http://127.0.0.1:8000/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(form),
    });

    const data = await res.json();
    setLoading(false);

    if (!res.ok) return alert(data.detail || "Signup failed");

    alert("Signup successful!");
    window.location.href = "/login";
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center"
      style={{ minHeight: "100vh", background: "#f3f6fb" }}
    >
      <div
        className="card p-4 shadow-sm"
        style={{
          width: "350px",
          borderRadius: "14px",
          background: "white",
        }}
      >
        <h3 className="text-center mb-3 fw-bold">Create Account</h3>

        <form onSubmit={submit}>
          {/* Username */}
          <div className="mb-3">
            <input
              className="form-control"
              placeholder="Username"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              required
            />
          </div>

          {/* Email + OTP */}
          <div className="mb-3">
            <div className="input-group">
              <input
                type="email"
                className="form-control"
                placeholder="Email"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                required
              />
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={sendEmailOtp}
                disabled={emailVerified}
              >
                OTP
              </button>
            </div>

            {emailOtpSent && !emailVerified && (
              <div className="input-group mt-2">
                <input
                  className="form-control"
                  placeholder="Enter Email OTP"
                  value={emailOtp}
                  onChange={(e) => setEmailOtp(e.target.value)}
                />
                <button
                  className="btn btn-success btn-sm"
                  type="button"
                  onClick={verifyEmailOtp}
                >
                  ✔
                </button>
              </div>
            )}

            {emailVerified && (
              <div className="alert alert-success py-1 mt-2 text-center">
                Email Verified
              </div>
            )}
          </div>

          {/* Phone + OTP */}
          <div className="mb-3">
            <div className="input-group">
              <input
                className="form-control"
                placeholder="Mobile"
                value={form.phone}
                onChange={(e) => setForm({ ...form, phone: e.target.value })}
                required
              />
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={sendPhoneOtp}
                disabled={phoneVerified}
              >
                OTP
              </button>
            </div>

            {phoneOtpSent && !phoneVerified && (
              <div className="input-group mt-2">
                <input
                  className="form-control"
                  placeholder="Enter Phone OTP"
                  value={phoneOtp}
                  onChange={(e) => setPhoneOtp(e.target.value)}
                />
                <button
                  type="button"
                  className="btn btn-success btn-sm"
                  onClick={verifyPhoneOtp}
                >
                  ✔
                </button>
              </div>
            )}

            {phoneVerified && (
              <div className="alert alert-success py-1 mt-2 text-center">
                Phone Verified
              </div>
            )}
          </div>

          <input
            className="form-control mb-3"
            placeholder="Full Name"
            value={form.full_name}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
            required
          />

          <input
            className="form-control mb-3"
            placeholder="Password"
            type="password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />

          <button
            className="btn btn-primary w-100 fw-bold"
            disabled={loading || !emailVerified || !phoneVerified}
          >
            {loading ? "Creating..." : "Signup"}
          </button>
        </form>

        <p className="text-center mt-3">
          <a href="/login" className="text-decoration-none fw-semibold">
            Already have an account? Login
          </a>
        </p>
      </div>
    </div>
  );
};

export default Signup;
