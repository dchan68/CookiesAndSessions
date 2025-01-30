import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  //setting cookie expiry
  cookie: {
    maxAgpe: 1000 * 60 * 60 * 24 //1000 millisecond * 60 to get 1 min * 60 * 24 = 1 day
  }
}))

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", function(req, res){
  //this route will get req.user from passport.use route thanks to cb() line 132 since that route will do the authentication, hence why login route was commented out
  console.log(req.user)
  if (req.isAuthenticated() == true){
    res.render("secrets.ejs")
  } else {
    res.redirect("/login");
  }
})

//this will trigger the strategy named "local" in line 134
app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
}))

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", //RETURNING * will return just the new user that just registered
            [email, hash]
          );
          const user = result.rows[0];
          //once we call login, it automatically authenticate users and redirects to /secrets
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  // const email = req.body.username;
  // const loginPassword = req.body.password;

  // try {
  //   const result = await db.query("SELECT * FROM users WHERE email = $1", [
  //     email,
  //   ]);
  //   if (result.rows.length > 0) {
  //     const user = result.rows[0];
  //     const storedHashedPassword = user.password;
  //     bcrypt.compare(loginPassword, storedHashedPassword, (err, result) => {
  //       if (err) {
  //         console.error("Error comparing passwords:", err);
  //       } else {
  //         if (result) {
  //           res.render("secrets.ejs");
  //         } else {
  //           res.send("Incorrect Password");
  //         }
  //       }
  //     });
  //   } else {
  //     res.send("User not found");
  //   }
  // } catch (err) {
  //   console.log(err);
  // }
});

passport.use("local", new Strategy(async function verify(username, password, cb){
  console.log(username);
  console.log(password);
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            //null bc no error is being returned
            return cb(null, user);
          } else {
            //return false bc user is not authenticated, so when we go back to /secrets route, it knows user is not authenticated
            return cb(null, false)
          }
        }
      });
    } else {
      return cb("User not found");
    }
  } catch (err) {
    return cb(err);
  }
}))

//save data of user that is logged in to local storage
passport.serializeUser( function(user, cb) {
  cb(null, user);
})

//pass user information using deserialization so website can get hold of it when user returns
passport.deserializeUser( function(user, cb) {
  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
