var express = require('express');
var router = express.Router();

// I have no idea what I'm doing
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var LDAPStrategy = require('passport-ldap').Strategy;

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.render('login');
});

// General login page
router.get('/login', function (req, res){
  console.log("Opening login page.");
  res.render('login');
});

// General logout page
router.get('/logout', function (req, res){
  req.logout();
  res.redirect('/auth/login');
});

// Local login POST method
router.post('/local', passport.authenticate('local'), function (req, res) {
  // If this function is called, auth was successful
  // req.user has the authed user
  res.redirect('/auth/success');
});

// Google oauth2 method
// redirect user for authentication
// Once signed in, user is redirected to /google/callback
router.get('/google', passport.authenticate('google', {
  scope: 'profile'
}));

// Google will redirect the user to this URL after auth.
// Finish the process by verifying the assertion.
router.get('/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/auth/invalid'
  }),
  function (req, res) {
    // auth successful
    res.redirect('/account/details');
  }
);

router.post('/ldap', passport.authenticate('ldap', {
  successRedirect: '/auth/success',
  failureRedirect: '/auth/invalid'
}));

router.get('/success',
  function (req, res, next) {
    res.send('Authentication successful ^_^ ');
    console.log("Logged in: ", req.user);
});

router.get('/invalid', function (req, res) {
  res.send('Authentication FAILED -_-;');
  console.log("NOT logged in: ", req.user);
});

router.get('/error', function (req, res) {
  res.send('Authentication ERROR >,<');
  console.log("Log in ERROR: ", req);
});

module.exports = router;
