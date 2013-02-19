# Passport-Atlassian-Crowd

[Passport](http://passportjs.org/) strategy for authenticating [Atlassian Crowd](http://www.atlassian.com/software/crowd/)
given a username and password.

This module lets you authenticate using a username and password in your Node.js
applications.  By plugging into Passport, atlassian crowd authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Installation

    $ npm install passport-atlassian-crowd

## Usage

#### Configure Strategy

The atlassian-crowd authentication strategy authenticates users using a username and
password via a REST call to your Crowd server.  The strategy requires a `verify` callback, which accepts these
credentials and calls `done` providing a user.  This strategy can also be used with JIRA running as a crowd server.
A valid application will have to be configured in Atlassian Crowd to be allowed to make requests.

Pass an optional `retrieveGroupMemberships:true` flag to populate a `groups` array on the userprofile
with all the groups the user is a member of in Crowd.

    passport.use(new AtlassianCrowdStrategy({
            crowdServer:"http://localhost:2990/jira",
            crowdApplication:"nodejs",
            crowdApplicationPassword:"password",
            retrieveGroupMemberships:false
        },
        function (userprofile, done) {
            Users.findOrCreate(userprofile, function(err,user) {
                if(err) return done(err);
                return done(null, user);
            });
        }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'atlassian-crowd'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/login', 
      passport.authenticate('atlassian-crowd', { failureRedirect: '/login' }),
      function(req, res) {
        res.redirect('/');
      });

## Examples

For a complete, working example, refer to the [login example](https://bitbucket.org/knecht_andreas/passport-atlassian-crowd/src/master/examples/login).

## Changes

* 0.0.3 - Added support for newer version of Crowd REST API (contributed by Frank Febbraro)

## License

(The MIT License)

Copyright (c) 2012 Andreas Knecht

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
