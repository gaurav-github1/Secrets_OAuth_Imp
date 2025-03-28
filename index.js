import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import pgSession from "connect-pg-simple";
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const PgStore = pgSession(session);

// Database connection
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Create the sessions table before starting the application
async function initialize() {
  try {
    await db.connect();
    
    // Create sessions table if it doesn't exist
    await db.query(`
      CREATE TABLE IF NOT EXISTS "sessions" (
        "sid" varchar NOT NULL,
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "sessions_pkey" PRIMARY KEY ("sid")
      )
    `);
    
    await db.query(`
      CREATE INDEX IF NOT EXISTS "IDX_sessions_expire" ON "sessions" ("expire")
    `);
    
    // Create users table if it doesn't exist
    await db.query(`
      CREATE TABLE IF NOT EXISTS "users" (
        "id" SERIAL PRIMARY KEY,
        "email" varchar(255) UNIQUE NOT NULL,
        "password" varchar(255) NOT NULL,
        "secret" text
      )
    `);
    
    console.log("Database tables initialized successfully");
  } catch (error) {
    console.error("Database initialization error:", error);
    process.exit(1);
  }
}

// Session configuration with PostgreSQL store
app.use(
  session({
    store: new PgStore({
      pool: db,
      tableName: 'sessions',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === 'production',
    }
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query(
        "SELECT secret FROM users WHERE email = $1",
        [req.user.email]
      );
      const secret = result.rows[0]?.secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", {
          secret: "Yes, you can put your secret😉.",
        });
      }
    } catch (error) {
      console.log(error);
      res.status(500).send("An error occurred");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

// Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.status(500).send("Registration failed");
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Login after registration failed:", err);
              return res.status(500).send("Login after registration failed");
            }
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Registration failed");
  }
});

app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  const email = req.user.email;
  try {
    await db.query(
      "UPDATE users SET secret = $1 WHERE email = $2",
      [secret, email]
    );
    res.redirect("/secrets");
  } catch (error) {
    console.log(error);
    res.status(500).send("Failed to save secret");
  }
});

// Local strategy setup
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        
        // Handle Google-authenticated users
        if (storedHashedPassword === "google") {
          return cb(null, false, { message: "Please use Google login for this account" });
        }
        
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false, { message: "Incorrect password" });
            }
          }
        });
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      console.log(err);
      return cb(err);
    }
  })
);

// Google strategy setup with dynamic callback URL
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log("Google profile:", profile.email);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        console.error("Google authentication error:", err);
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Initialize database and start server
initialize().then(() => {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}).catch(err => {
  console.error("Failed to start application:", err);
});