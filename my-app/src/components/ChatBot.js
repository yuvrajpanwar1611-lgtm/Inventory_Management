import React, { useState } from "react";

const ChatBotWidget = () => {
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Floating Chat Icon */}
      <div
        onClick={() => setOpen(!open)}
        style={{
          position: "fixed",
          bottom: "20px",
          right: "20px",
          background: "#007bff",
          color: "white",
          width: "60px",
          height: "60px",
          borderRadius: "50%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "24px",
          cursor: "pointer",
          boxShadow: "0 4px 10px rgba(0,0,0,0.3)",
          zIndex: 9999,
        }}
      >
        💬
      </div>

      {/* Chat Window */}
      {open && (
        <div
          style={{
            position: "fixed",
            bottom: "90px",
            right: "20px",
            width: "380px",
            height: "520px",
            background: "white",
            borderRadius: "10px",
            overflow: "hidden",
            boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
            zIndex: 99999,
          }}
        >
          <iframe
            src="http://localhost:5678/webhook/4e32944a-85b7-46dc-91d5-04dd81c46c15/chat"
            style={{
              width: "100%",
              height: "100%",
              border: "none",
            }}
            title="AI Assistant"
          ></iframe>
        </div>
      )}
    </>
  );
};

export default ChatBotWidget;
