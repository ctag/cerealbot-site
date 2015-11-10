//////////////////////
// SQLite functions //
//////////////////////

var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('./main.sqlite');
var sql = {};

sql.getAllParts = function (callback) {
  db.serialize(function () {
    db.all('SELECT * FROM parts',
  function (err, rows) {
    console.log("SQL errors: ", err);
    if (err === null) {
      if (typeof(callback) === 'function') {
        callback(err, rows);
      }
    }
  });
  });
};

sql.createPart = function (part, user, callback) {
  var id;
  if (user.authMethod === 'google') {
    id = user.id;
  } else if (user.authMethod === 'ldap') {
    id = user.uid;
  } else {
    console.log("SQL Create Part error, no user id!");
    return;
  }
  db.serialize(function () {
    db.run('INSERT INTO parts '+
    '(originalName, filename, path, size, userId, infoX, infoY, infoZ, infoFacets, infoShells, infoVolume, infoRepaired)'+
    ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  part.originalname, part.filename, part.path, part.size, id,
  part.info.x, part.info.y, part.info.z, part.info.facets, part.info.shells, part.info.volume, part.info.repair,
  function (err) {
    console.log("SQL errors: ", err);
    if (err === null) {
      console.log("Num rows changed: ", this.changes);
    }
    callback(err, this.changes);
  });
  });
};

sql.createAccount = function (user, callback) {
  db.serialize(function () {
    db.run('INSERT INTO users (id, authMethod, givenName, familyName, accountType) VALUES (?, ?, ?, ?, ?)',
  user.id, user.authMethod, user.givenName, user.familyName, user.accountType,
  function (err) {
    console.log("SQL errors: ", err);
    if (err === null) {
      console.log("Num rows changed: ", this.changes);
    }
    //callback(err, this.changes);
  });
  });
};

sql.login = function (user, callback) {
  db.serialize(function () {
    db.run('UPDATE users SET numLogins=?, lastLogIn=? WHERE id=?;',
  (user.numLogins+1), new Date().toString(), user.id,
  function (err) {
    console.log("SQL errors: ", err);
    if (err === null) {
      console.log("Num rows changed: ", this.changes);
    }
    //callback(err, this.changes);
  });
  });
};

sql.fetchUser = function (id, authMethod, callback) {
  if (req.authMethod !== 'google') {
    callback(null);
  }
  if (typeof(req.user.id) !== 'string') {
    callback(null);
  }
  var googleId = req.user.id;
  //db.serialize(function () {
    console.log("Finding account for " + googleId);
    db.get('SELECT * FROM users WHERE googleId=?;', googleId,
    function (err, row) {
      if (typeof(row) === 'undefined') {
        callback(null);
      }
      //console.log("returned row: ", row);
      callback(row);
    });
  //});
};

// user = req.user
sql.fetchActiveUser = function (user, callback) {
  // Make sure req is valid
  if (user.authMethod !== 'google' && user.authMethod !== 'ldap' && user.authMethod !== 'local') {
    callback(null);
  }
  if (typeof(user.id) !== 'string') {
    callback(null);
  }
  // Check for google auth
  if (user.authMethod === 'google') {
    console.log("Finding google user for " + user.id);
    db.get('SELECT * FROM users WHERE authMethod=? AND id=?;', user.authMethod, user.id,
    function (err, row) {
      // row is undefined if user is not in DB
      callback(row);
      return;
    });
  }
};

module.exports = sql;
