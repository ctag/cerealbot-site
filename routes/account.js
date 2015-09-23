var express = require('express');
var router = express.Router();
var restrict = require('../midware/restrict.js');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Account Pages' });
});

router.get('/index', function(req, res, next) {
  res.redirect('/');
});

router.get('/home', function(req, res, next) {
  res.redirect('/');
});

router.get('/details',
restrict.auth,
function(req, res, next) {
  console.log("Account details for: ", req.user);
  res.render('details', {
    title: 'Account Details',
    user: req.user
  });
});

module.exports = router;
