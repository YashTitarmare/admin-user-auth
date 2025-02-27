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

// DataBase Name is UserDB  --> collections is users
  const userSchema = new mongoose.Schema({       
    name: { type: String, required: true, unique: true },  
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  }, { versionKey: false }); // for the __v remove 
  
// DataBase Name is UserDB  --> collections is adminbds

  const adminSchema = new mongoose.Schema({
    sname: { type: String, required: true, unique: true },  
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  })  

  /*  const userSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },  
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  }); 
*/

  userSchema.index({ name: 1 }, { unique: true }); // add the unqiueness
 

const User = mongoose.model("User", userSchema);

const AdminDB = mongoose.model("AdminDB", adminSchema);

 

// alreay hte ADMIN DATA
 // const ADMIN_CREDENTIALS = { email: "admin@example.com", password: "admin123" };
// MongoServerError: E11000 duplicate key error collection: userDB.admindbs index: email_1 dup key: { e
app.post("/admin/register", async (req, res) => {
  const { sname, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new AdminDB({ sname, email, password: hashedPassword });

  await newUser.save();
  res.json({ message: "Admin registered successfully" });
});



//admin Login






// user register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });

  await newUser.save();
  res.json({ message: "User registered successfully" });
});


















// admin see the user data
