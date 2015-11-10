//////////////////////
// Route Middleware //
//////////////////////

var restrict = {};

function validAuth(req) {
  console.log("Valid Auth: ", req.isAuthenticated());
  if (req.isAuthenticated()) {
    return (true);
  }
  return (false);
}

function validUser(req) {
  console.log("Valid User: ", req.user.authMethod, ". Account Type: ", req.user.accountType);
  if (typeof(req.user.authMethod) !== 'string') {
    return (false);
  }
  if (req.user.accountType === 'student' || req.user.accountType === 'teacher' ||
  req.user.accountType === 'admin' || req.user.authMethod === 'ldap') {
  console.log("Valid user.");
  return (true);
  }
  return(false);
}

function validTeacher(req) {
  if (typeof(req.authMethod) !== 'string') {
    return (false);
  }
  if (req.user.accountType === 'teacher' || req.user.accountType === 'admin') {
  console.log("Valid teacher.");
  return (true);
  }
  return(false);
}

function validAdmin(req) {
  if (typeof(req.authMethod) !== 'string') {
    return (false);
  }
  if (req.user.accountType === 'admin') {
  console.log("Valid admin.");
  return (true);
  }
  return(false);
}

// Only allow valid passport sessions (anyone with a Google account)
restrict.auth = function (req, res, next) {
  if (validAuth(req)) {
    console.log("checkAuth authenticated for: ");
    return next();
  }
  // User is not valid/existant
  console.log("restrictAuth invalid. ");
  res.redirect('/auth/login');
};

// Only allow valid SQL-listed users (student, teacher, admin, ...)
restrict.user = function (req, res, next) {
  if (validAuth(req) && validUser(req)) {
    return next();
  }
  // User is not logged in from SQL
  console.log("restrictUser invalid. ");
  res.redirect('/auth/login');
};

// Only allow valid SQL-listed teachers
restrict.teacher = function (req, res, next) {
  if (validAuth(req) && validTeacher(req)) {
    return next();
  }
  // Teacher is not logged in from SQL
  console.log("restrictTeacher invalid. ");
  res.redirect('/auth/login');
};

// Only allow valid SQL-listed admins (myself)
restrict.admin = function (req, res, next) {
  if (validAuth(req) && validAdmin(req)) {
    return next();
  }
  // Admin is not logged in from SQL
  console.log("restrictAdmin invalid. ");
  res.redirect('/auth/login');
};

module.exports = restrict;
