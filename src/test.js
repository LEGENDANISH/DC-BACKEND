const { io } = require("socket.io-client");

// Your JWT token
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJjbWZjbHR4ejUwMDA0aTJmc2FsbWtvczFkIiwiZW1haWwiOiJhc2hpc2gxMjNAZ21haWwuY29tIiwiaWF0IjoxNzU3NTk1NzY2LCJleHAiOjE3NTgyMDA1NjZ9.NLHN_W7JME7to-u_XSt-KSw9oKiDsvteb7jK__-ZbtE";

// Your real channelId
const channelId = "cmfclnher0001i2fs5tlbv4qj";

const socket = io("http://localhost:3000", { // ✅ Fixed port
  auth: { token },
  transports: ['websocket'],
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000
});

// Connection
socket.on("connect", () => {
  console.log("✅ Connected:", socket.id);
  console.log("➡️  Joining channel:", channelId);
  // socket.emit("join_channel", channelId);
});
socket.on("ready", () => {
  console.log("Ready received");
  socket.emit("join_channel", channelId, (ack) => {
    console.log("join_channel ack:", ack);
  });
});
// Confirm join
socket.on("channel_joined", (data) => {
  console.log("📢 Joined channel successfully:", data);
  
  // Send a test message via WebSocket
  setTimeout(() => {
    console.log("📤 Sending WebSocket message...");
    socket.emit("message", {
      channelId,
      content: "Hello from WebSocket! 🚀"
    });
  }, 1000);
});

// Listen for live messages
socket.on("message", (msg) => {
  console.log("📩 LIVE MESSAGE RECEIVED:", JSON.stringify(msg, null, 2));
});

// Error handling
socket.on("error", (err) => {
  console.error("❌ WebSocket Error:", err);
});

// Connection error
socket.on("connect_error", (err) => {
  console.error("🔌 Connection Error:", err.message);
});

// Also test REST API
const testRestAPI = async () => {
  try {
    const response = await fetch(`http://localhost:3000/api/channels/${channelId}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        content: "Hello from REST API! 📡"
      })
    });

    const result = await response.json();
    console.log("📡 REST API Response:", result);
  } catch (error) {
    console.error("❌ REST API Error:", error);
  }
};

// Test REST API after connection is established
setTimeout(testRestAPI, 3000);