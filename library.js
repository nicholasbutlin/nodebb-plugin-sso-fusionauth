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
  const request = module.parent.require("request");

  const FusionAuth = {};
  FusionAuth.utils = {};

  const OAuth2Strategy = require("passport-oauth").OAuth2Strategy;

  // Use config.json for nconf
  const authurl = nconf.get("oauth:url");
  const providerName = nconf.get("oauth:name");

  const callBackUrl = "/auth/" + providerName + "/callback";

  // options for the oAuth2 Config
  const options = Object.freeze({
    authorizationURL: authurl + "/oauth2/authorize",
    tokenURL: authurl + "/oauth2/token",
    clientID: nconf.get("oauth:id"),
    clientSecret: nconf.get("oauth:secret"),
    userRoute: authurl + "/oauth2/introspect",
    passReqToCallback: true,
    callbackURL: nconf.get("url") + callBackUrl,
    logoutURL: authurl + "/oauth2/logout",
    scope: "user email"
  });

  /**
   * utils.parseUserReturn
   *
   *
   */
  FusionAuth.utils.parseUserReturn = function(data, callback) {
    // Find out what is available
    winston.info("[sso-fusionauth] data:" + JSON.stringify(data, null, 2));
    const re = /^([A-Za-z0-9._%+-])+/;

    var profile = {};
    profile.oAuthid = data.sub;
    profile.username = data.preferred_username
      ? data.preferred_username
      : re.match(data.email);
    profile.email = data.email;
    profile.isAdmin = data.roles[0] === "Admin";

    callback(null, profile);
  };

  /**
   * utils.getUidByOAuthid
   *
   *
   */
  FusionAuth.utils.getUidByOAuthid = function(oAuthid, callback) {
    db.getObjectField(providerName + "Id:uid", oAuthid, function(err, uid) {
      if (err) {
        console.log(err);
        return callback(err);
      }
      callback(null, uid);
    });
  };

  /**
   * getStrategy
   *
   *
   */
  FusionAuth.getStrategy = function(strategies, callback) {
    winston.info("[sso-fusionauth] getStrategy");

    OAuth2Strategy.Strategy.prototype.userProfile = function(
      accessToken,
      done
    ) {
      request.post(
        {
          url: options.userRoute,
          form: { client_id: options.clientID, token: accessToken }
        },
        function(err, req) {
          if (err) {
            return done(err);
          }

          try {
            var json = JSON.parse(req.body);
            FusionAuth.utils.parseUserReturn(json, function(err, profile) {
              if (err) {
                return done(err);
              }
              profile.provider = providerName;

              done(null, profile);
            });
          } catch (err) {
            done(err);
          }
        }
      );
    };

    passport.use(
      providerName,
      new OAuth2Strategy.Strategy(options, function(
        req,
        accessToken,
        refeshToken,
        profile,
        done
      ) {
        FusionAuth.login(profile, function(err, user) {
          if (err) {
            console.log(err);
            return done(err);
          }

          authenticationController.onSuccessfulLogin(req, user.uid);
          done(null, user);
        });
      })
    );

    strategies.push({
      name: providerName,
      url: "/auth/" + providerName,
      callbackURL: callBackUrl,
      icon: "fa-check-square",
      scope: (options.scope || "").split(",")
    });

    callback(null, strategies);
  };

  /**
   * login
   *
   *
   */
  FusionAuth.login = function(profile, callback) {
    FusionAuth.utils.getUidByOAuthid(profile.oAuthid, function(err, uid) {
      winston.info("[sso-fusionauth] getUidByOAuthid from login");

      if (err) {
        winston.error(err);
        return callback(err);
      }

      if (uid !== null) {
        // Existing User
        callback(null, {
          uid: uid
        });
      } else {
        // New User
        const onSuccessfulUID = function(uid) {
          // Save provider-specific information to the user
          User.setUserField(uid, providerName + "Id", profile.oAuthid);
          db.setObjectField(providerName + "Id:uid", profile.oAuthid, uid);

          if (profile.isAdmin) {
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

        User.getUidByEmail(profile.email, function(err, uid) {
          if (err) {
            return callback(err);
          }

          if (!uid) {
            User.create(
              {
                username: profile.username,
                email: profile.email
              },
              function(err, uid) {
                if (err) {
                  return callback(err);
                }

                onSuccessfulUID(uid);
              }
            );
          } else {
            onSuccessfulUID(uid); // Existing account -- merge
          }
        });
      }
    });
  };

  /**
   * deleteUserData
   *
   *
   */
  FusionAuth.deleteUserData = function(data, callback) {
    async.waterfall(
      [
        async.apply(User.getUserField, data.uid, providerName + "Id"),
        function(oAuthIdToDelete, next) {
          db.deleteObjectField(providerName + "Id:uid", oAuthIdToDelete, next);
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

  /**
   * logout
   *
   *
   */
  FusionAuth.logout = function(req, res, next) {
    winston.info("[sso-fusionauth] logout");
    authenticationController.logout(req, res, next);
    request(
      { url: options.logoutURL, qs: { client_id: options.clientID } },
      function(err, response, body) {
        if (err) {
          console.log(err);
          return;
        }
        console.log("Get response: " + response.statusCode);
      }
    );
  };

  // If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
  FusionAuth.whitelistFields = function(params, callback) {
    params.whitelist.push(providerName + "Id");
    callback(null, params);
  };

  module.exports = FusionAuth;
})(module);
