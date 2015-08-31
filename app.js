/**
 * Utility webpages for cerealbox
 * Christopher Bero - csb0019@uah.edu
 */

/////////////
// modules //
/////////////

var express = require('express');
var path = require('path');
var util = require('util');
var os = require('os');
var numCores = os.cpus().length;
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var extend = require('extend');
var multer = require('multer');
var upload = multer({ dest: 'uploads/', fileFilter: fileFilter });

var session = require('express-session');
var cluster = require('cluster');
var cstore = require('cluster-store');

var sql = require('./midware/sql.js');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var LDAPStrategy = require('passport-ldap').Strategy;
var restrict = require('./midware/restrict.js');

var secrets = require('./secrets.json');
var route_root = require('./routes/index.js');
var route_auth = require('./routes/auth.js');
var route_api = require('./routes/api.js');
var route_account = require('./routes/account.js');
var app = express();

///////////////
// app setup //
///////////////

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// express-session must be set up before passport.session
var cstore_opts = {
  sock: '/tmp/memstore.sock',
  store: cluster.isMaster && new require('express-session/session/memory')(),
  serve: cluster.isMaster,
  connect: cluster.isWorker,
  standalone: (1 === numCores)
};
var cstore_instance;
cstore.create(cstore_opts).then(function (store) {
  console.log("Cluster-Store created.");
  store.get(id, function (err, data) {
    console.log("Cluster-Store setup: ", data);
  });
  cstore_instance = store;
});

app.use(session({
  secret: secrets.sessionSecret,
  store: cstore_instance, /* I have no idea what I'm doing */
  resave: false,
  saveUninitialized: false /* Is saved anyway because of passportjs */
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(function (req, res, next) {
  console.log('\n[' + new Date() + '] Request from: ', req.headers['x-forwarded-for']);
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// directory based routes
app.use('/', route_root);
app.use('/auth', route_auth);
app.use('/api', route_api);
app.use('/account', route_account);
//app.use(multer( {dest: './uploads/'} ));

app.get('/part/upload', function (req, res, next) {
  res.render('upload');
});

function fileFilter (req, file, cb) {
  var fileExtension = file.originalname.split('.').pop();
  console.log("Ext: ", fileExtension);
  if (file.mimetype === 'application/sla') {
    if (fileExtension === 'STL' || fileExtension === 'stl') {
      cb(null, true);
      return;
    }
  }
  console.log("File filter is rejecting a bad upload: ", file.originalname);
  cb(null, false);

  cb(new Error("File filter rejected a bad upload"));
}

app.post('/part/upload',
restrict.user,
upload.single('part'),
function (req, res, next) {
  //console.log("Form's body (text): ", req.body);
  console.log("File: ", req.file);
  sql.createPart(req.file, req.user, function (err, changes) {
    res.render('uploaded', { title: 'Upload landing page', err: err, changes: changes });
  });
});

////////////////////
// passport setup //
////////////////////

passport.serializeUser(function(user,done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Strategy for local auth
passport.use(new LocalStrategy(
  function (username, password, done) {
    console.log("Auth check: ", username, password);
    if (username === secrets.root.username && password === secrets.root.password) {
      return done(null, username);
    } else {
      return done(null, false, {message: "Login failed"});
    }
  }
));

// Strategy for Google oauth2
passport.use(new GoogleStrategy({
    clientID: secrets.google.clientID,
    clientSecret: secrets.google.clientSecret,
    callbackURL: secrets.google.callbackURL
  },
  function(accessToken, refreshToken, profile, done) {
    // insert identifier into database
    //console.log(accessToken, refreshToken, profile);
    profile.authMethod = 'google';
    sql.fetchActiveUser(profile, function(user) {
      console.log("SQL found: ", typeof(user));
      if (typeof(user) === 'undefined') {
        profile.type = 'visitor';
      } else {
        // User found in database
        extend(true, profile, user);
      }
      sql.login(profile);
      console.log("User logged in with: ", profile);
      return done(null, profile);
    });
  }
));

// Ldap strategy for ML256 members
var ldap_opts = {
  server: {
    url: secrets.ldap.url
  },
  authMode: 1, /* 0: Windows, 1: Unix */
  uidTag: 'uid',
  debug: true,
  usernameField: 'username',
  passwordField: 'password',
  base: secrets.ldap.base,
  search: {
    filter: secrets.ldap.filter,
    scope: 'sub',
    attributes: ['givenName','displayName','uid'],
    sizeLimit: 1
  },
  searchAttributes: ['uid']
};
passport.use(new LDAPStrategy(
  ldap_opts,
  function(profile, done) {
    console.log("LDAP Profile: ", profile);
    profile.authMethod = 'ldap';
    profile.type = 'visitor';
    return done(null, profile);
  }
));

////////////////////
// error handlers //
////////////////////

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

module.exports = app;
