require("dotenv").config();   
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs"); // hashing
const jwt = require("jsonwebtoken");  
const cors = require("cors"); //
const crypto = require('crypto');  // jwt seccrtiy id creation
const { type } = require("os");

const app = express();
app.use(express.json()); // allows the bodies enter data in josn form  for Apis


app.use(cors());

const PORT = process.env.PORT || 5000;

//const jwtSecret = crypto.randomBytes(32).toString('base64');

const jwtSecret = process.env.JWT_SECRET || "fallbackSecret";  // Use environment variable for JWT secret

// const jwtSecret = Math.floor(100000 + Math.random() * 900000);

//const jwtSecret = crypto.randomBytes(32).writeInt8(2,0);


mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));


  const userSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },  
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  });
  



  userSchema.index({ name: 1 }, { unique: true });
 

  const User = mongoose.model("User", userSchema);
 

// alreay hte ADMIN DATA
const ADMIN_CREDENTIALS = { email: "admin@example.com", password: "admin123" };

// user restiom
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });

  await newUser.save();
  res.json({ message: "User registered successfully" });
});

//admin Login
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body; // exteacting the emil and password for the request body
console.log(jwtSecret);
  if (email === ADMIN_CREDENTIALS.email && password === ADMIN_CREDENTIALS.password) {
    const token = jwt.sign({ role: "admin" }, jwtSecret, { expiresIn: "1h" });   // here if i give the JWT has digit is not work beacusee the args have get only the srting 

// simple mail reprent the enter data and other one is for all ready build data is show in this



    return res.json({ message: "Login successful", token });

  } else {
    return res.status(401).json({ error: "Invalid credentials" });

  }



});






// admin see the user data

/* Old
app.get("/admin/users", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1]; // Extract the token

  //const token = req.headers.authorization;

  if (!token) return res.status(403).json({ error: "Access Denied" });

  try {
    //const verified = jwt.verify(token, JWT_SECRET);
    const verified = jwt.verify(token, jwtSecret);
    
    if (verified.role === "admin") {
      User.find().then((users) => res.json(users));
    } else {
      res.status(403).json({ error: "Unauthorized" });
    }
  } catch (error) {
    res.status(400).json({ error: "Invalid Token" });
  }
});

*/

app.get("/admin/users", (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ error: "Access Denied" });
  }

  const token = authHeader.split(" ")[1]; // Extract token after "Bearer"

  try {
    const verified = jwt.verify(token, jwtSecret);

    if (verified.role === "admin") {
      User.find().then((users) => res.json(users));
    } else {
      res.status(403).json({ error: "Unauthorized" });
    }
  } catch (error) {
    res.status(400).json({ error: "Invalid Token" });
  }
});





app.get("/admin/user-count", async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    res.json({ totalUsers });
  } catch (error) {
    console.error("Error counting users:", error);
    res.status(500).json({ error: "Server error" });
  }
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
