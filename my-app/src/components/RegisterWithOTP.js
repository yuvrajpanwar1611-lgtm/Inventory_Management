import React, { useState } from "react";
import axios from "axios";

const RegisterWithOTP = () => {
  const [mobile, setMobile] = useState("");
  const [otp, setOtp] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [verified, setVerified] = useState(false);

  const sendOTP = async () => {
    await axios.post("http://localhost:8000/send-otp", { mobile });
    alert("OTP sent (Static OTP is 123456)");
    setOtpSent(true);
  };

  const verifyOTP = async () => {
    const res = await axios.post("http://localhost:8000/verify-otp", {
      mobile,
      otp
    });

    if (res.data.verified) {
      alert("✅ Mobile Verified!");
      setVerified(true);
    } else {
      alert("❌ Invalid OTP");
    }
  };

  return (
    <div className="container mt-4">
      <h3>User Registration</h3>

      <input
        className="form-control mb-2"
        placeholder="Enter Mobile Number"
        value={mobile}
        onChange={(e) => setMobile(e.target.value)}
      />

      {!otpSent && (
        <button className="btn btn-primary" onClick={sendOTP}>
          Send OTP
        </button>
      )}

      {otpSent && !verified && (
        <>
          <input
            className="form-control mt-2"
            placeholder="Enter OTP"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
          />

          <button className="btn btn-success mt-2" onClick={verifyOTP}>
            Verify OTP
          </button>
        </>
      )}

      {verified && <h5 className="text-success mt-3">✅ Mobile Verified</h5>}
    </div>
  );
};

export default RegisterWithOTP;
