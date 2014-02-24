var anonymous = {
  is_authenticated: false
};

var _login_url = null;

/**
 * Middleware for user session management.
 *
 * @api public
 */
module.exports = function (login_url) {
  _login_url = login_url;

  return function (req, res, next) {
    if (req.session === undefined) throw Error('current-user requires session support.');
    if (!req.session.current_user) req.session.current_user = anonymous;
    res.locals.current_user = req.session.current_user;

    if (!req.login_user && !req.logout_user) {
      req.login_user = _login_user(res);
      req.logout_user = _logout_user(res);
    }

    next();
  };
};

function _login_user(res) {
  /**
   * User login.
   *
   * @param {Object} user
   * @api public
   */
  return function (user) {
    user.is_authenticated = true;
    res.locals.current_user = this.session.current_user = user;
  };
}

function _logout_user(res) {
  /**
   * User logout.
   *
   * @param {Object} user
   * @api public
   */
  return function () {
    res.locals.current_user = this.session.current_user = anonymous;
  };
}

/**
 * Middlewae: only login user can access the given route.
 *
 * @api public
 */
module.exports.require_login = function (req, res, next) {
  if (req.session.current_user.is_authenticated) next();
  else
    if (_login_url) res.redirect(_login_url);
    else res.end('Permission denied, please login first.');
}
