const express = require("express");
const http = require("http");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

require("dotenv").config();

const app = express();
// Trust Render reverse proxy
app.set('trust proxy', 1);
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
console.error("Missing required environment variables.");
process.exit(1);
}

const allowedOrigins = [
"https://muneer1999.github.io"
];

app.use(helmet());

app.use(cors({
origin: allowedOrigins,
methods: ["GET", "POST"]
}));

app.use(express.json({ limit: "20kb" }));

const loginLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 10,
standardHeaders: true,
legacyHeaders: false
});

const sessionLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 20,
standardHeaders: true,
legacyHeaders: false
});

app.use("/api/login", loginLimiter);
app.use("/api/sessions", sessionLimiter);

const io = new Server(server, {
cors: {
origin: allowedOrigins,
methods: ["GET", "POST"]
}
});

const sessions = new Map();

function randomToken() {
return crypto.randomBytes(32).toString("hex");
}

function makeCode() {
return crypto.randomInt(100000, 1000000).toString();
}

function adminAuth(req, res, next) {
const header = req.headers.authorization || "";
const token = header.replace(/^Bearer\s+/i, "");

try {
const decoded = jwt.verify(token, JWT_SECRET);


if (decoded.role !== "admin") {
  return res.status(403).json({
    error: "Admin access required."
  });
}

req.admin = decoded;
next();


} catch {
res.status(401).json({
error: "Authentication required."
});
}
}

function safeSession(session) {
return {
id: session.id,
code: session.code,
createdAt: session.createdAt,
sharing: session.sharing,
connected: session.connected,
device: session.device || null,
location: session.location || null
};
}

function removeSession(id) {
const session = sessions.get(id);

if (!session) return;

io.to(id).emit("session-ended");

io.in(id).socketsLeave(id);

sessions.delete(id);

io.to("dashboard").emit("session-removed", {
id
});
}

app.get("/", (req, res) => {
res.json({
name: "Android Security Lab",
status: "online"
});
});

/* ADMIN LOGIN */

app.post("/api/login", (req, res) => {
const username = String(req.body.username || "");
const password = String(req.body.password || "");

const validUser =
crypto.timingSafeEqual(
Buffer.from(
crypto.createHash("sha256").update(username).digest("hex")
),
Buffer.from(
crypto.createHash("sha256").update(ADMIN_USERNAME).digest("hex")
)
);

const validPassword =
crypto.timingSafeEqual(
Buffer.from(
crypto.createHash("sha256").update(password).digest("hex")
),
Buffer.from(
crypto.createHash("sha256").update(ADMIN_PASSWORD).digest("hex")
)
);

if (!validUser || !validPassword) {
return res.status(401).json({
error: "Invalid username or password."
});
}

const token = jwt.sign(
{
role: "admin",
username: ADMIN_USERNAME
},
JWT_SECRET,
{
expiresIn: "8h"
}
);

res.json({
success: true,
token
});
});

/* CREATE PARTICIPANT SESSION AFTER EXPLICIT CONSENT */

app.post("/api/sessions", (req, res) => {
const sharing = req.body.sharing || {};

const allowed = [
"location",
"camera",
"microphone",
"device"
];

const selected = {};

for (const feature of allowed) {
selected[feature] = sharing[feature] === true;
}

if (!Object.values(selected).some(Boolean)) {
return res.status(400).json({
error: "Select at least one sharing feature."
});
}

const id = crypto.randomUUID();
const participantToken = randomToken();

const session = {
id,
code: makeCode(),
participantToken,
createdAt: new Date().toISOString(),
sharing: selected,
connected: false,
participantSocketId: null,
device: null,
location: null
};

sessions.set(id, session);

res.status(201).json({
id,
code: session.code,
participantToken,
message: "Sharing session created."
});
});

/* PRIVATE DASHBOARD SESSION LIST */

app.get("/api/sessions", adminAuth, (req, res) => {
res.json({
sessions: Array.from(sessions.values()).map(safeSession)
});
});

/* SOCKET AUTHENTICATION */

io.use((socket, next) => {
const token = socket.handshake.auth?.token;

if (!token) {
return next(new Error("Authentication required."));
}

try {
const decoded = jwt.verify(token, JWT_SECRET);


if (decoded.role === "admin") {
  socket.data.role = "admin";
  return next();
}


} catch {
// Check participant token.
}

for (const session of sessions.values()) {
if (session.participantToken === token) {
socket.data.role = "participant";
socket.data.sessionId = session.id;
return next();
}
}

next(new Error("Invalid session token."));
});

/* LIVE CONNECTIONS */

io.on("connection", socket => {

/* ADMIN DASHBOARD */

if (socket.data.role === "admin") {
socket.join("dashboard");


socket.emit(
  "active-sessions",
  Array.from(sessions.values()).map(safeSession)
);

/*
  Dashboard must call:
  socket.emit("watch-session", { id: sessionId })
  before viewing a participant's camera or microphone.
*/

socket.on("watch-session", data => {
  const id = String(data?.id || "");
  const session = sessions.get(id);

  if (!session) return;

  socket.join(id);

  socket.emit("watch-session-ready", {
    id
  });
});

/* ADMIN SENDS WEBRTC ANSWER TO PARTICIPANT */

socket.on("webrtc-answer", data => {
  const id = String(data?.id || "");
  const session = sessions.get(id);

  if (!session || !socket.rooms.has(id)) return;

  if (!session.sharing.camera && !session.sharing.microphone) {
    return;
  }

  io.to(id).emit("webrtc-answer", {
    description: data?.description
  });
});

/* ADMIN SENDS ICE CANDIDATE */

socket.on("webrtc-answer-ice", data => {
  const id = String(data?.id || "");
  const session = sessions.get(id);

  if (!session || !socket.rooms.has(id)) return;

  io.to(id).emit("webrtc-answer-ice", {
    candidate: data?.candidate
  });
});

return;


}

/* PARTICIPANT CONNECTION */

const sessionId = socket.data.sessionId;
const session = sessions.get(sessionId);

if (!session) {
socket.disconnect(true);
return;
}

socket.join(sessionId);

session.connected = true;
session.participantSocketId = socket.id;

io.to("dashboard").emit(
"session-updated",
safeSession(session)
);

/* LOCATION SHARING */

socket.on("share-location", data => {
if (!session.sharing.location) return;


const latitude = Number(data?.latitude);
const longitude = Number(data?.longitude);

if (
  !Number.isFinite(latitude) ||
  !Number.isFinite(longitude) ||
  latitude < -90 ||
  latitude > 90 ||
  longitude < -180 ||
  longitude > 180
) return;

session.location = {
  latitude,
  longitude,
  accuracy: Number(data.accuracy) || null,
  updatedAt: new Date().toISOString()
};

io.to("dashboard").emit("location-updated", {
  id: session.id,
  location: session.location
});


});

/* DEVICE INFORMATION */

socket.on("share-device", data => {
if (!session.sharing.device) return;


session.device = {
  browser: String(data?.browser || "").slice(0, 100),
  platform: String(data?.platform || "").slice(0, 100),
  language: String(data?.language || "").slice(0, 30),
  screen: String(data?.screen || "").slice(0, 40),
  updatedAt: new Date().toISOString()
};

io.to("dashboard").emit("device-updated", {
  id: session.id,
  device: session.device
});


});

/* PARTICIPANT SENDS WEBRTC OFFER TO DASHBOARD */

socket.on("webrtc-offer", data => {
if (!session.sharing.camera && !session.sharing.microphone) {
return;
}


if (!data?.description) return;

io.to("dashboard").emit("webrtc-offer", {
  id: session.id,
  description: data.description
});


});

/* PARTICIPANT SENDS ICE CANDIDATE */

socket.on("webrtc-offer-ice", data => {
if (!session.sharing.camera && !session.sharing.microphone) {
return;
}


if (!data?.candidate) return;

io.to("dashboard").emit("webrtc-offer-ice", {
  id: session.id,
  candidate: data.candidate
});


});

/* PARTICIPANT ENDS SHARING */

socket.on("stop-sharing", () => {
removeSession(sessionId);
});

/* PARTICIPANT DISCONNECTS */

socket.on("disconnect", () => {
const current = sessions.get(sessionId);


if (!current || current.participantSocketId !== socket.id) {
  return;
}

current.connected = false;
current.participantSocketId = null;

io.to("dashboard").emit(
  "session-updated",
  safeSession(current)
);


});

});

/* ADMIN ENDS A SESSION */

app.post("/api/sessions/:id/end", adminAuth, (req, res) => {
const id = req.params.id;

if (!sessions.has(id)) {
return res.status(404).json({
error: "Session not found."
});
}

removeSession(id);

res.json({
success: true
});
});

/* AUTOMATIC SESSION EXPIRY */

setInterval(() => {
const expiry = Date.now() - 60 * 60 * 1000;

for (const session of sessions.values()) {
if (Date.parse(session.createdAt) < expiry) {
removeSession(session.id);
}
}
}, 60 * 1000);

/* START SERVER */

server.listen(PORT, () => {
console.log(
`Android Security Lab server running on port ${PORT}`
);
});
