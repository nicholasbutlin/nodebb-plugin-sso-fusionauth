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

  const OAuth = {};
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
   * getStrategy
   *
   *
   */
  OAuth.getStrategy = function(strategies, callback) {
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
            OAuth.parseUserReturn(json, function(err, profile) {
              if (err) {
                return done(err);
              }
              profile.provider = providerName;

              done(null, profile);
            });
          } catch (e) {
            done(e);
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
        OAuth.login(
          {
            oAuthid: profile.id,
            handle: profile.displayName,
            email: profile.emails[0].value,
            isAdmin: profile.isAdmin
          },
          function(err, user) {
            if (err) {
              console.log(err);
              return done(err);
            }

            authenticationController.onSuccessfulLogin(req, user.uid);
            done(null, user);
          }
        );
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
   * parseUserReturn
   *
   *
   */
  OAuth.parseUserReturn = function(data, callback) {
    // Find out what is available
    // winston.info("[sso-fusionauth] data:" + JSON.stringify(data, null, 2));

    var profile = {};
    profile.id = data.sub;
    profile.displayName = data.name;
    profile.emails = [{ value: data.email }];
    profile.isAdmin = data.roles[0] === "Admin";

    callback(null, profile);
  };

  /**
   * login
   *
   *
   */
  OAuth.login = function(payload, callback) {
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
          User.setUserField(uid, providerName + "Id", payload.oAuthid);
          db.setObjectField(providerName + "Id:uid", payload.oAuthid, uid);

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
    db.getObjectField(providerName + "Id:uid", oAuthid, function(err, uid) {
      if (err) {
        console.log(err);
        return callback(err);
      }
      callback(null, uid);
    });
  };

  OAuth.deleteUserData = function(data, callback) {
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

  OAuth.logout = function(req, res, nex) {
    // authenticationController.logout(req, res, nex);

    winston.info("[sso-fusionauth] logout");
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
  OAuth.whitelistFields = function(params, callback) {
    params.whitelist.push(providerName + "Id");
    callback(null, params);
  };

  module.exports = OAuth;
})(module);
