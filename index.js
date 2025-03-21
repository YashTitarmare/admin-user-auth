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
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  const admin = await AdminDB.findOne({ email });
  if (!admin) {
    return res.status(401).json({ error: "Invalid credentials" });
  }


  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

// jwt token greanaation
  const token = jwt.sign({ role: "admin", email: admin.email }, jwtSecret, { expiresIn: "1h" });

  res.json({ message: "Login successful", token });
});









// user register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });

  await newUser.save();
  res.json({ message: "User registered successfully" });
});


// User login 
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Find user in database
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  // Compare hashed password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(403).json({ error: "Unauthorized" });

  }

  // Generate JWT token
  const token = jwt.sign({ role: "user", email: user.email }, jwtSecret, { expiresIn: "1h" });

  res.json({ message: "Login successful", token });




});



// for admin to see the user enter data in the resister only for 
// Only  one admin ---- Multpies user 

// Without middleware 

app.get("/admin/users", async (req, res) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Access denied. No token provided." });
  }

  try {
    console.log("Received Token:", token);
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Decoded Token:", decoded);

    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admins only." });
    }

    const users = await User.find({}, { password: 0 });
    res.json({ users });

  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    res.status(401).json({ error: "Invalid token." });
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



/*  Connect for dashboard */

/*app.get("/dashboard", (req, res) => {
  res.json({
    message: "Welcome to the Dashboard",
    user: req.user, // Show logged-in user details
  });
});


mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("MongoDB Connected");
});

*/

/* Dashboard end */

/* Dashboardfor  geting the shop name and date with post reqeust  */










const dashboardSchema = new mongoose.Schema({
  shopName: String,
  date: Date,
  your_time: String,
});

const Dashboard = mongoose.model("Dashboard", dashboardSchema);

app.post("/dashboard", async (req, res) => {
  try {
    const { shopName, date } = req.body; 

    if (!shopName || !date) {
      return res.status(400).json({ error: "Shop name and date are required" });
    }

    let your_time = "10"; // here we apply the logic for the give the time for the user (logic code )

    const count = await Dashboard.countDocuments();  

    if (count == 5) {
      your_time = "25"; // check the if the count 5 means the taotal count is 5 then the 5 is tthe 25 otherwisie is 10 
    }

    const newEntry = new Dashboard({ shopName, date, your_time }); // Used `your_time` instead of `your_time` from request.
    await newEntry.save();

    res.json({ message: "Entry saved successfully", data: newEntry });
  } catch (error) {
    console.error("Server Error:", error); // Added console log to debug errors.
    res.status(500).json({ error: "Server Error" });
  }
});


/*

const dashboardSchema = new mongoose.Schema({
  shopName: String,
  date: Date,
  your_time:String,
});


const Dashboard = mongoose.model("Dashboard", dashboardSchema);

app.post("/dashboard", async (req, res) => {
  const { shopName, date,your_time} = req.body;

  if (!shopName || !date) {
    return res.status(400).json({ error: "Shop name and date are required" });
  }
  if (db.dashboards.count()==5){
    your_time='20',
  }

  try {
    const count = await Dashboard.countDocuments();  // Get the total count of documents

    if (count == 5) {
      your_time = "20";  // Corrected assignment
    }
    const newEntry = new Dashboard({ shopName, date,your_time });
    await newEntry.save();
    res.json({ message: " entry saved successfully", data: newEntry });
  } catch (error) {
    res.status(500).json({ error: " Server Error" });
  }
}); 

*/
























// Start Server


/* Dashboard post nd   */
// seting the   ID   filed in the dashboard with nature number  1 to infite   if the 1  then the fist time slot is give to  ID 1   user like 10:am the ID with 2   get 10:10 am 



app.get("/dashboard", async (req, res) => {
  const token = req.header("Authorization")?.split(" ")[1]; 

  if (!token) {
    return res.status(403).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret); 
    res.json({
      message: "Welcome to the Dashboard",
      user: decoded, // show all login deatils 
    });
  } catch (error) {
    res.status(401).json({ error: "Invalid token." });
  }
});




app.get("/users/booking-data", async (req, res) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Access denied. No token provided." });
  }

  try {
    console.log("Received Token:", token);
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Decoded Token:", decoded);

    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admins only." });
    }

    const users = await Dashboard.find({}, { password: 0 });
    res.json({ users });

  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    res.status(401).json({ error: "Invalid token." });
  }
});











app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
