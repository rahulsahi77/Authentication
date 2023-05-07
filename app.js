//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const saltRounds = 10;
 
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = new mongoose.model("User", userSchema);

// Requests----------------
app.get("/", (req, res) => {
    res.render("home");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

// for the registration of users
app.post("/register", async (req, res) => {
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        const hash = await bcrypt.hash(req.body.password, salt);
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
        await newUser.save();
        res.render("secrets");
    } catch (err) {
        console.error(err);
        res.status(500).send("Error creating user");
    }
});

// checking if the entered data matches with the database entries, if yes then let user log in
app.post("/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    try {
        const foundUser = await User.findOne({ email: username });
        if (foundUser) {
            // Check if the password matches using bcrypt.compare method
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if (result === true) {
                    res.render("secrets");
                } else {
                    res.status(401).send("Incorrect password");
                }
            });
        } else {
            res.status(404).send("User not found");
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Error logging in");
    }
});

app.listen(3000, () => {
    console.log("server started on port 3000."); 
});
