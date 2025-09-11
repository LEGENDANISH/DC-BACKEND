const { io } = require("socket.io-client");

// 👉 Replace with your JWT
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJjbWZjbHR4ejUwMDA0aTJmc2FsbWtvczFkIiwiZW1haWwiOiJhc2hpc2gxMjNAZ21haWwuY29tIiwiaWF0IjoxNzU3NTk1NzY2LCJleHAiOjE3NTgyMDA1NjZ9.NLHN_W7JME7to-u_XSt-KSw9oKiDsvteb7jK__-ZbtE";




// 👉 Your real channelId
const channelId = "cmfclnher0001i2fs5tlbv4qj";

const socket = io("http://localhost:3000", {
  auth: { token },
  transports: ['websocket'],
  reconnection: true,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000
});

// ✅ Connection
socket.on("connect", () => {
  console.log("✅ Connected:", socket.id);

  // Try joining the channel
  console.log("➡️  Joining channel:", channelId);
  socket.emit("join_channel", channelId);
  
  // Also try sending typing indicator to test connection
  setTimeout(() => {
    console.log("⌨️  Sending typing start...");
    socket.emit("typing_start", channelId);
  }, 1000);
});

// ✅ Confirm join
socket.on("channel_joined", (data) => {
  console.log("📢 Joined channel:", data);

  // Send a test message after joining
  setTimeout(() => {
    console.log("📤 Sending test message...");
    socket.emit("message", {
      channelId,
      content: "Hello from test.js 🚀"
    });
  }, 1000);
});

// ✅ Channel join error
socket.on("error", (err) => {
  console.error("❌ Error:", err);
});

// ✅ Live messages
socket.on("message", (msg) => {
  console.log("📩 Live message received:", msg);
});

// ✅ Typing indicators
socket.on("typing_start", (data) => {
  console.log("✍️ User typing:", data);
});

socket.on("typing_stop", (data) => {
  console.log("🛑 Typing stopped:", data);
});

// ✅ Status updates
socket.on("user_status_update", (data) => {
  console.log("🔔 User status update:", data);
});

// ✅ Ready event (server sends this after auth)
socket.on("ready", (data) => {
  console.log("🟢 Ready event received:", data);
});

// ✅ Channel left confirmation
socket.on("channel_left", (data) => {
  console.log("🚪 Channel left:", data);
});

// ✅ Catch ALL events (debug)
socket.onAny((event, ...args) => {
  console.log("📡 Event received:", event, args);
});

// ✅ Connection error
socket.on("connect_error", (err) => {
  console.error("🔌 Connection Error:", err.message);
});

// ✅ Disconnect
socket.on("disconnect", (reason) => {
  console.log("🔌 Disconnected:", reason);
});