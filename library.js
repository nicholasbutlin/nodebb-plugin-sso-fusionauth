"use strict";

(function(module) {
  const User = require.main.require("./src/user");
  const Groups = require.main.require("./src/groups");
  const db = require.main.require("./src/database");
  const authenticationController = require.main.require(
    "./src/controllers/authentication"
  );

  const async = require("async");

  const passport = module.parent.require("passport");
  const nconf = module.parent.require("nconf");
  const winston = module.parent.require("winston");

  // Use config.json for nconf
  const authurl = nconf.get("oauth:url");
  const constants = Object.freeze({
    type: "oauth2",
    name: "chargetogether",
    oauth2: {
      authorizationURL: authurl + "/oauth2/authorize",
      tokenURL: authurl + "/oauth2/token",
      clientID: nconf.get("oauth:id"),
      clientSecret: nconf.get("oauth:secret")
    },
    userRoute: authurl + "/oauth2/userinfo"
  });

  const OAuth = {};
  let passportOAuth;
  let opts;

  winston.error("[sso-fusionauth] starting");

  /**
   * getStrategy
   *
   *
   */
  OAuth.getStrategy = function(strategies, callback) {
    passportOAuth = require("passport-oauth")["OAuth2Strategy"];
    winston.info("[sso-fusionauth] Get Strategy");

    // OAuth 2 options
    opts = constants.oauth2;
    opts.callbackURL =
      nconf.get("url") + "/auth/" + constants.name + "/callback";

    passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
      console.log(accessToken);
      this._oauth2.get(constants.userRoute, accessToken, function(
        err,
        body,
        res
      ) {
        if (err) {
          return done(err);
        }

        try {
          var json = JSON.parse(body);
          winston.info("[sso-fusionauth]:" + JSON.stringify(json));
          OAuth.parseUserReturn(json, function(err, profile) {
            if (err) return done(err);
            profile.provider = constants.name;

            done(null, profile);
          });
        } catch (e) {
          done(e);
        }
      });
    };

    opts.passReqToCallback = true;

    winston.info("[sso-fusionauth]" + JSON.stringify(opts));

    passport.use(
      constants.name,
      new passportOAuth(opts, function(req, token, secret, profile, done) {
        winston.info("[sso-fusionauth]:" + JSON.stringify(token));
        OAuth.login(
          {
            oAuthid: profile.id,
            handle: profile.displayName,
            email: profile.emails[0].value,
            isAdmin: profile.isAdmin
          },
          function(err, user) {
            if (err) {
              return done(err);
            }

            authenticationController.onSuccessfulLogin(req, user.uid);
            done(null, user);
          }
        );
      })
    );

    strategies.push({
      name: constants.name,
      url: "/auth/" + constants.name,
      callbackURL: "/auth/" + constants.name + "/callback",
      icon: "fa-check-square",
      scope: (constants.scope || "").split(",")
    });

    callback(null, strategies);
  };

  /**
   * parseUserReturn
   *
   *
   */
  OAuth.parseUserReturn = function(data, callback) {
    // Find out what is available by uncommenting this line:
    winston.info("[sso-fusionauth] data:" + JSON.stringify(data));

    var profile = {};
    profile.id = data.sub;
    profile.displayName = data.name;
    profile.emails = [{ value: data.email }];

    callback(null, profile);
  };

  /**
   * login
   *
   *
   */
  OAuth.login = function(payload, callback) {
    winston.error("[sso-fusionauth] login");
    OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
      if (err) {
        return callback(err);
      }

      if (uid !== null) {
        // Existing User
        callback(null, {
          uid: uid
        });
      } else {
        // New User
        var success = function(uid) {
          // Save provider-specific information to the user
          User.setUserField(uid, constants.name + "Id", payload.oAuthid);
          db.setObjectField(constants.name + "Id:uid", payload.oAuthid, uid);

          if (payload.isAdmin) {
            Groups.join("administrators", uid, function(err) {
              callback(err, {
                uid: uid
              });
            });
          } else {
            callback(null, {
              uid: uid
            });
          }
        };

        User.getUidByEmail(payload.email, function(err, uid) {
          if (err) {
            return callback(err);
          }

          if (!uid) {
            User.create(
              {
                username: payload.handle,
                email: payload.email
              },
              function(err, uid) {
                if (err) {
                  return callback(err);
                }

                success(uid);
              }
            );
          } else {
            success(uid); // Existing account -- merge
          }
        });
      }
    });
  };

  /**
   * getUidByOAuthid
   *
   *
   */
  OAuth.getUidByOAuthid = function(oAuthid, callback) {
    winston.error("[sso-fusionauth] getUidByOAuthid");
    db.getObjectField(constants.name + "Id:uid", oAuthid, function(err, uid) {
      if (err) {
        return callback(err);
      }
      callback(null, uid);
    });
  };

  OAuth.deleteUserData = function(data, callback) {
    async.waterfall(
      [
        async.apply(User.getUserField, data.uid, constants.name + "Id"),
        function(oAuthIdToDelete, next) {
          db.deleteObjectField(
            constants.name + "Id:uid",
            oAuthIdToDelete,
            next
          );
        }
      ],
      function(err) {
        if (err) {
          winston.error(
            "[sso-oauth] Could not remove OAuthId data for uid " +
              data.uid +
              ". Error: " +
              err
          );
          return callback(err);
        }

        callback(null, data);
      }
    );
  };

  // If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
  OAuth.whitelistFields = function(params, callback) {
    params.whitelist.push(constants.name + "Id");
    callback(null, params);
  };

  module.exports = OAuth;
})(module);
