const express = require("express");
const jwt = require("jsonwebtoken");
const { Issuer } = require("openid-client");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());

let client;
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// Middleware to verify JWT token
const verifyJWT = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ error: "Invalid token", details: err.message });
  }
};

// Initialize OIDC client
(async function start() {
  try {
    const googleIssuer = await Issuer.discover("https://accounts.google.com");

    client = new googleIssuer.Client({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uris: [`${BASE_URL}/auth/callback`],
      response_types: ["code"],
    });

    console.log("OIDC client initialized");
  } catch (err) {
    console.error("OIDC discovery error:", err);
    process.exit(1);
  }
})();

// Login route - redirect to Google
app.get("/login", (req, res) => {
  if (!client) {
    return res.status(500).json({ error: "OIDC client not initialized" });
  }

  const authorizationUrl = client.authorizationUrl({
    scope: "openid profile email",
    state: Math.random().toString(36).substring(7),
    nonce: Math.random().toString(36).substring(7),
  });

  res.redirect(authorizationUrl);
});

// Callback route - exchange code for token
app.get("/auth/callback", async (req, res) => {
  try {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(`${BASE_URL}/auth/callback`, params);
    const userInfo = await client.userinfo(tokenSet);

    // Create JWT token with user info
    const jwtToken = jwt.sign(
      {
        sub: userInfo.sub,
        email: userInfo.email,
        name: userInfo.name,
        picture: userInfo.picture,
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    );

    // Set JWT in httpOnly cookie
    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.redirect("/profile");
  } catch (err) {
    console.error("Callback error:", err);
    res
      .status(400)
      .json({ error: "Authentication failed", details: err.message });
  }
});

// Protected route - profile
app.get("/profile", verifyJWT, (req, res) => {
  res.json({
    message: "Welcome to your profile",
    user: req.user,
  });
});

// Home route
app.get("/", (req, res) => {
  const token = req.cookies.token;

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      res.json({
        message: "Authenticated",
        user: decoded,
        links: { profile: "/profile", logout: "/logout" },
      });
    } catch (err) {
      res.json({ message: "Guest", links: { login: "/login" } });
    }
  } else {
    res.json({ message: "Guest", links: { login: "/login" } });
  }
});

// Logout route - clear JWT cookie
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out successfully" });
});

// Refresh token endpoint (optional)
app.post("/refresh-token", verifyJWT, (req, res) => {
  const newToken = jwt.sign(
    {
      sub: req.user.sub,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
    },
    JWT_SECRET,
    { expiresIn: "24h" },
  );

  res.cookie("token", newToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    maxAge: 24 * 60 * 60 * 1000,
  });

  res.json({ message: "Token refreshed", token: newToken });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`JWT SSO server running on port ${PORT}`);
});
