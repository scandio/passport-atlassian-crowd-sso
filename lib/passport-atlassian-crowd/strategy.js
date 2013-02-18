/**
 * Module dependencies.
 */
var passport = require('passport'),
    https = require('https'),
    http = require('http'),
    URL = require('url'),
    util = require('util'),
    BadRequestError = require('./errors/badrequesterror');


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) throw new Error('atlassian-crowd authentication strategy requires a verify function');

    if (!options.crowdServer) {
        throw new Error("atlassian-crowd strategy requires a crowd server url");
    }

    this._crowdServer = options.crowdServer;
    this._crowdApplication = options.crowdApplication;
    this._crowdApplicationPassword = options.crowdApplicationPassword;

    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';

    passport.Strategy.call(this);
    this.name = 'atlassian-crowd';
    this._verify = verify;
    this._retrieveGroupMemberships = options.retrieveGroupMemberships;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


function _parseProfile(crowdUser) {
    return {
        provider:'atlassian-crowd',
        id:crowdUser.name,
        username:crowdUser.name,
        displayName:crowdUser["display-name"],
        name:{
            familyName:crowdUser["last-name"],
            givenName:crowdUser["first-name"]
        },
        email:crowdUser.email,
        emails:[
            {value:crowdUser.email}
        ],
        _json:crowdUser
    };
}

function _lookup(obj, field) {
    if (!obj) {
        return null;
    }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
        var prop = obj[chain[i]];
        if (typeof(prop) === 'undefined') {
            return null;
        }
        if (typeof(prop) !== 'object') {
            return prop;
        }
        obj = prop;
    }
    return null;
}


function _handleResponse(response, callback) {
    var result = "";
    response.on("data", function (chunk) {
        result += chunk;
    });
    response.on("close", function (err) {
        callback(response, result);
    });
    response.addListener("end", function () {
        callback(response, result);
    });
}

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
    options = options || {};
    var username = _lookup(req.body, this._usernameField) || _lookup(req.query, this._usernameField);
    var password = _lookup(req.body, this._passwordField) || _lookup(req.query, this._passwordField);

    if (!username || !password) {
        return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
    }
    var self = this;

    var http_library = https;
    var parsedUrl = URL.parse(this._crowdServer, true);
    if (parsedUrl.protocol == "https:" && !parsedUrl.port) {
        parsedUrl.port = 443;
    }

    // As this is OAUth2, we *assume* https unless told explicitly otherwise.
    if (parsedUrl.protocol != "https:") {
        http_library = http;
    }

    var postData = JSON.stringify({ "value":password });
    var applicationAuth = 'Basic ' + new Buffer(this._crowdApplication + ':' + this._crowdApplicationPassword).toString('base64');

    function verified(err, user, info) {
        if (err) {
            return self.error(err);
        }
        if (!user) {
            return self.fail(info);
        }
        self.success(user, info);
    }

    function handleGroupResponse(response, result) {
        if (response.statusCode === 200) {
            var resultObject = JSON.parse(result);
            var groups = [];
            resultObject.groups.forEach(function (group) {
                groups.push(group.name);
            });

            return groups;

        } else if (response.statusCode >= 400 && response.statusCode < 500) {
            var error = JSON.parse(result);
            console.log("Error retrieving groups for user '" + username + "': " + error.message + " [" + error.reason + "]");
            return self.fail();
        } else {
            return self.error(new Error("Invalid response from Crowd Server '" + self._crowdServer +
                "' [" + response.statusCode + "]: " + result));
        }
    }

    function handleAuthenticationResponse(response, result) {
        if (response.statusCode === 200) {
            var crowdUser = JSON.parse(result);
            var userprofile = _parseProfile(crowdUser);
            userprofile._raw = result;

            if (self._retrieveGroupMemberships) {
                var groupResult = "";
                var groupRequest = http_library.get({
                    host:parsedUrl.hostname,
                    port:parsedUrl.port,
                    path:parsedUrl.pathname + "/rest/usermanagement/latest/user/group/nested?username=" + username,
                    headers:{
                        "Content-Type":"application/json",
                        "Accept":"application/json",
                        "Authorization":applicationAuth
                    }
                }, function (response) {
                    _handleResponse(response, function (response, groupResult) {
                        userprofile.groups = handleGroupResponse(response, groupResult);
                        return self._verify(userprofile, verified);
                    });
                });
                groupRequest.on('error', function (err) {
                    self.error(new Error("Error connecting to Crowd Server '" + self._crowdServer + "': " + err));
                });
            } else {
                return self._verify(userprofile, verified);
            }
        } else if (response.statusCode >= 400 && response.statusCode < 500) {
            var error = {"message":result};
            try {
                error = JSON.parse(result);
            } catch (err) {
            }

            var logMsg = "Error authenticating user '" + username + "' on '" + self._crowdServer + "': " + error.message;
            if (error.reason) {
                logMsg += " [" + error.reason + "]";
            }
            console.log(logMsg);
            return self.fail();
        } else {
            return self.error(new Error("Invalid response from Crowd Server '" + self._crowdServer +
                "' [" + response.statusCode + "]: " + result));
        }
    }

    var crowdRequest = http_library.request({
        host:parsedUrl.hostname,
        port:parsedUrl.port,
        path:parsedUrl.pathname + "/rest/usermanagement/latest/authentication?expand=attributes&username=" + username,
        method:"POST",
        headers:{
            "Content-Type":"application/json",
            "Accept":"application/json",
            "Content-Length":postData.length,
            "Authorization":applicationAuth
        }
    }, function (response) {
        _handleResponse(response, handleAuthenticationResponse);
    });
    crowdRequest.on('error', function (err) {
        self.error(new Error("Error connecting to Crowd Server '" + self._crowdServer + "': " + err));
    });

    crowdRequest.write(postData);
    crowdRequest.end();
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
