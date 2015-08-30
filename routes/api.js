var express = require('express');
var router = express.Router();

router.get('/googleInfo',
function (req, res, next) {
  console.log("SQL Request: ", req.user.id);
  res.json(req.user);
});

router.get('/createAccount',
function (req, res, next) {
  console.log("Creating account for: ", req.user.displayName);
  sqlCreateAccount(req.user.name.givenName, req.user.name.familyName, req.user.id);
  res.send("Account requested");
});

router.get('/account/details',
function (req, res, next) {
  console.log("Listing account details for: ", req.user.displayName);
  res.send(req.user);
});

router.post('/account/create',
function (req, res, next) {
  var user = req.body;
  console.log("Creating account for: ", user);
  sqlCreateAccount(user);
  res.send("Account requested.");
});

router.get('/viewAllAccounts',
function (req, res, next) {
  console.log("Creating account for: ", req.user.displayName);
  //sqlCreateAccount(req.user.name.givenName, req.user.name.familyName, req.user.id);
  res.send("Account requested");
});


module.exports = router;
