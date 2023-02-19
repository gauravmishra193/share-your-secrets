// ******** look into the repo for all the authentication versions of this application ********

// What is a Session?
// This series of requests and responses, each associated with the same user, is known as a session.
// In a session, we make a STATEFUL protocol with the use of HTTP Cookies which are transmitted to the server with every request and response of the user.
// The HTTP req and res is a STATELESS protocol meaning every req can be understood in isolation- w/o context of previous req.
// A session is used to maintain a numb of states, one of them are Authentication State, also known as Login State, and to maintain many other unrelated to authentication state.

// What is 'passport'?
// Passport is designed to isolate Authentication State from the other states that may be store in the session.
// session must be initialised using express-session module in order to use make login sessions.


//jshint esversion:6

const dotenv = require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const passport = require('passport'); // authentication middleware for node.js
const passportLocalMongoose = require('passport-local-mongoose'); // this package will automatically salt and hash our passwords automatically w/o us doing it explicitly
const session = require('express-session'); // creates the cookies and stores the contents.
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

  

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
    // session: false
}));


app.use(passport.initialize()); // this is initialisation of passport package
app.use(passport.session());
// app.use(methodOverride("_method"));

app.use(express.static("public"));

mongoose.set('strictQuery', true);

mongoose.connect("mongodb://127.0.0.1/userDB");


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(findOrCreate);
userSchema.plugin(passportLocalMongoose); // this will hash and salt the passwords and save the user into the mongoDB database.


const User = mongoose.model("User", userSchema);


// 'passport-local' configuration ==============


passport.use(User.createStrategy()); 

passport.serializeUser(function(user, cb) { // serialize creates the cookies and stuffs it with the data namely user's identification into the cookie.
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) { // deserialize allows passport to crumbles the cookie and discover the message inside which is who this user is so that we can authenticate them on our server. 
  process.nextTick(function() {
    return cb(null, user);
  });
});

// Following is another method to serialize and deserialize:
// passport.serializeUser(User.serializeUser()); 
// passport.deserializeUser(User.deserializeUser()); 

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) { // there is no such query as findOrCreate in mongoose, so we found a npm package "mongoose-findorcreate" and installed and required in our poroject.
      return cb(err, user);
    });
  }
));



// '/auth/google' ROUTE ====================================================================================================================

app.get("/auth/google", passport.authenticate("google", { scope: ['profile'] }));


// '/auth/google/secrets' ROUTE ====================================================================================================================

app.get("/auth/google/secrets", passport.authenticate('google', { failureRedirect : "/login"}),
    function(req, res){
        console.log()
        res.redirect("/secrets")
    });


// '/' ROUTE ====================================================================================================================


app.get("/", function(req, res){
    res.render("home");
});


// LOGIN route ====================================================================================================================


app.get("/login", checkNotAuthenticated, (req, res) => {
    res.render("login", {message: ""});
}); 

    
app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


    

    

// LOGOUT route ====================================================================================================================



app.post("/logout", (req, res) =>{
    req.logout(function(err){
        if(err) console.log(err);
        else res.redirect("/login");
    });
});



// SECRETS route ====================================================================================================================

app.get("/secrets", function(req, res){
    
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) console.log(err);
        else{
            if(foundUsers){
                res.render("secrets", {SecretArray: foundUsers})
            }
        }
    })
});



// REGISTER route ====================================================================================================================


app.get("/register", checkNotAuthenticated, (req, res) =>{
    res.render("register");
});



app.post("/register", (req, res) =>{
   
    User.register({username: req.body.username}, req.body.password, function(err, user){  
                            // user is the new registered user
                            // the register method comes from the passport-local-mongoose packege and it will save us from creating new user using a vatiable
                            // and saving using newUser.save(). register() will do it all by itself.
        if(err){
            console.log(err);
            res.redirect("/register");
        } 
        else{
            passport.authenticate("local")(req, res, function(){
                            // this callback will be triggered if the authentication was successful and we managed to successfully setup a cookies that saved the current logged in session.
                            // upon the authentication, a login session is established
                res.redirect("/secrets");
            })
        }
    }); 
});
    


// SUBMIT route ====================================================================================================================


app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else res.redirect("/login", {message: "Login! Authentication Failed!"});
});

app.post("/submit", function(req, res){

    const submittedSecret = req.body.secret;

    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.

    User.findById(req.user.id, function(err, foundUser){
        if(err) console.log(err);
        else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })
})



// RANDOM functions ====================================================================================================================


function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/secrets");
    }
    else{
        next();
    }
    
}



// LISTEN ====================================================================================================================


app.listen(3000, function() {
  console.log("Server is live on port 3000");
});

