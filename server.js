var _ = require("lodash");
var express = require("express");
var bodyParser = require("body-parser");
var morgan = require('morgan');
var jwt = require('jsonwebtoken');
var passport = require("passport");
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var config = require('./config/main.js');
var users = require('./models/users.js');
var port = 3000;

var app = express();

// Use body-parser to get POST requests for API use
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Log requests to console
app.use(morgan('dev'));

// Initialize Passport and use Strategy
app.use(passport.initialize());

// PASSPORT-JWT SETUP
var jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeader();
jwtOptions.secretOrKey = 'tasmanianDevil';

passport.use(new JwtStrategy(jwtOptions, function(jwt_payload, done){
  var user = users[_.findIndex(users, {id: jwt_payload.id})];
  if (user) {
    next(null, user);
  } else {
    next(null, false);
  }
}));

// Routing
app.get("/", function(req, res) {
  res.send('Hello! The protected view is at http://localhost:' + port + '/secret');
});

app.post("/login", function(req, res) {

  if(req.body.name && req.body.password){
    var name = req.body.name;
    var password = req.body.password;
  }

  // usually this would be a database call:
  var user = users[_.findIndex(users, {name: req.body.name})];
  if(!user){
    res.status(401).json({message:"no such user found"});
  }

  if(user.password === req.body.password) {
    // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
    var payload = { id: user.id };
    var token = jwt.sign(payload, jwtOptions.secretOrKey);
    res.json({ message: "ok", token: token });
  } else {
    res.status(401).json({ message: "passwords did not match" });
  }
});

// Secret Test
app.get("/secret", function(req, res){
  var token = req.body.token || req.query.token || req.headers['x-access-token'];

  if (token) {
    jwt.verify(token, jwtOptions.secretOrKey, function(err, decoded) {
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });
      } else {
        res.json({ success: true, message: 'authenticated' });
      }
    });

  } else {
    res.status(403).json({ success: false, message: "No token provided" });
  }
});

// Server Listen
app.listen(port, function() {
  console.log("Running on port 3000...");
});
