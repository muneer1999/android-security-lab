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

app.use("/api/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10
}));

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
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Authentication required." });
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

  io.to("dashboard").emit("session-removed", { id });
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

  const validUser = username === ADMIN_USERNAME;
  const validPassword = password === ADMIN_PASSWORD;

  if (!validUser || !validPassword) {
    return res.status(401).json({
      error: "Invalid username or password."
    });
  }

  const token = jwt.sign(
    { role: "admin", username: ADMIN_USERNAME },
    JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({
    success: true,
    token
  });
});

/* CREATE A CONSENT-BASED SHARING SESSION */

app.post("/api/sessions", (req, res) => {
  const sharing = req.body.sharing || {};

  const allowed = ["location", "camera", "microphone", "device"];

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
    // Check participant token below.
  }

  for (const session of sessions.values()) {
    if (
      session.participantToken &&
      token === session.participantToken
    ) {
      socket.data.role = "participant";
      socket.data.sessionId = session.id;
      return next();
    }
  }

  next(new Error("Invalid session token."));
});

/* LIVE CONNECTIONS */

io.on("connection", socket => {

  if (socket.data.role === "admin") {
    socket.join("dashboard");

    socket.emit("active-sessions",
      Array.from(sessions.values()).map(safeSession)
    );

    return;
  }

  const sessionId = socket.data.sessionId;
  const session = sessions.get(sessionId);

  if (!session) {
    socket.disconnect(true);
    return;
  }

  socket.join(sessionId);
  session.connected = true;

  io.to("dashboard").emit("session-updated", safeSession(session));

  /* LOCATION SHARING */

  socket.on("share-location", data => {
    if (!session.sharing.location) return;

    const latitude = Number(data?.latitude);
    const longitude = Number(data?.longitude);

    if (
      !Number.isFinite(latitude) ||
      !Number.isFinite(longitude) ||
      latitude < -90 || latitude > 90 ||
      longitude < -180 || longitude > 180
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

  /* WEBRTC SIGNALING */

  socket.on("webrtc-offer", data => {
    if (!session.sharing.camera && !session.sharing.microphone) return;

    io.to("dashboard").emit("webrtc-offer", {
      id: session.id,
      description: data?.description
    });
  });

  socket.on("webrtc-answer", data => {
    socket.to(sessionId).emit("webrtc-answer", {
      description: data?.description
    });
  });

  socket.on("webrtc-ice", data => {
    socket.to(sessionId).emit("webrtc-ice", {
      candidate: data?.candidate
    });
  });

  socket.on("stop-sharing", () => {
    removeSession(sessionId);
  });

  socket.on("disconnect", () => {
    session.connected = false;

    io.to("dashboard").emit(
      "session-updated",
      safeSession(session)
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

  res.json({ success: true });
});

/* CLEAN UP OLD SESSIONS */

setInterval(() => {
  const expiry = Date.now() - 60 * 60 * 1000;

  for (const session of sessions.values()) {
    if (Date.parse(session.createdAt) < expiry) {
      removeSession(session.id);
    }
  }
}, 60 * 1000);

server.listen(PORT, () => {
  console.log(`Android Security Lab server running on port ${PORT}`);
});
