require("dotenv").config();
const express = require("express");
const session = require("express-session");
const { Issuer } = require("openid-client");
const helmet = require("helmet");
const crypto = require("crypto");

const app = express();

app.use(helmet());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // true in production with HTTPS
      sameSite: "lax",
    },
  }),
);

let client;

// 1️⃣ Discover Google OIDC config dynamically
(async () => {
  const googleIssuer = await Issuer.discover("https://accounts.google.com");

  client = new googleIssuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uris: [`${process.env.BASE_URL}/callback`],
    response_types: ["code"],
  });
})();

app.get("/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");

  req.session.state = state;
  req.session.nonce = nonce;

  const authorizationUrl = client.authorizationUrl({
    scope: "openid email profile",
    prompt: "none",
    state,
    nonce,
  });

  res.redirect(authorizationUrl);
});

app.get("/callback", async (req, res) => {
  try {
    const params = client.callbackParams(req);

    const tokenSet = await client.callback(
      `${process.env.BASE_URL}/callback`,
      params,
      {
        state: req.session.state,
        nonce: req.session.nonce,
      },
    );

    const userInfo = tokenSet.claims();

    req.session.user = {
      id: userInfo.sub,
      email: userInfo.email,
      name: userInfo.name,
      picture: userInfo.picture,
    };

    res.redirect("/dashboard");
  } catch (err) {
    console.error("Callback Error:", err);
    res.status(500).send("Authentication failed");
  }
});

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect("/login");
}

app.get("/dashboard", isAuthenticated, (req, res) => {
  res.send(`
    <h1>Welcome ${req.session.user.name}</h1>
    <p>Email: ${req.session.user.email}</p>
    <img src="${req.session.user.picture}" width="100"/>
    <br><br>
    <a href="/logout">Logout</a>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/", (req, res) => {
  res.send(`
    <h2>Home</h2>
    <a href="/login">Login with Google</a>
  `);
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
