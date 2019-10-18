// Copyright 2017 Telefónica Digital España S.L.
//
// This file is part of UrboCore API.
//
// UrboCore API is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// UrboCore API is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with UrboCore API. If not, see http://www.gnu.org/licenses/.
//
// For those usages not covered by this license please contact with
// iot_support at tid dot es

'use strict';

var common = require('./common');
var config = require('../config');
var express = require('express');
var router = express.Router();
var check = require('./check');
var graph = require('./graph');
var Model = new require('./model.js');
var cfgData = config.getData();
var OAuth2 = require('./oauth2').OAuth2;
var url = require('url');

router.post('/token/new', check.password, function(req, res, next) {
  common.insertJwtToken(res.user, req.app.get('jwtTokenExpiration'), req.app.get('jwtTokenSecret'), function (error, data) {
    if (error)
      return next(error);

    res.json(data);
  });
});

router.get('/user/graph', check.checkToken, function(req, res, next) {
  graph.getUserGraph(res.user.id,function(err,data) {
    if (err)
      return next(err);
    res.json(data);
  });
});

// Enable Fiware Oauth2
if (cfgData.auth.idm_active) {
  var oauth = new OAuth2(
    cfgData.idm.client_id,
    cfgData.idm.client_secret,
    cfgData.idm.type,
    cfgData.idm.url,
    cfgData.idm.authorize_url,
    cfgData.idm.access_token_url,
    cfgData.idm.introspect_url,
    cfgData.idm.user_info_url,
    cfgData.idm.callback_url
  );
}

// Redirection to IDM authentication portal
router.get('/idm/auth', function(req, res) {
  if (!cfgData.auth.idm_active) {
    res.sendStatus(404);
  }
  var path = oauth.getAuthorizeUrl(cfgData.idm.response_type, req.query.cb);
  res.redirect(path);
});

// Handles requests from IDM with an access code
router.get('/idm/login', function(req, res, next) {
  if (!cfgData.auth.idm_active) {
    res.sendStatus(404);
  }

  // Using the access code goes again to the IDM to obtain the access_token
  oauth.getOAuthAccessToken(req.query.code, function (error1, response1) {
    if (error1) {
      return next(error1);
    }
    var access_token = response1.access_token;

    oauth.introspect(access_token, function (errorF, responseF){
      if(errorF) {
        return next(errorF);
      }
    });

    oauth.getUserInfo(access_token, function (error2, response2) {
      if (error2) {
        return next(error2);
      }

      var email = JSON.parse(response2).email;
      var roles = JSON.parse(response2).roles;

      var isValidUser = true
      var isAdmin = false

      if (cfgData.idm.user_role || cfgData.idm.admin_role) {
        if(!roles.includes(cfgData.idm.user_role)) {
          isValidUser = false
        }
        if(roles.includes(cfgData.idm.admin_role)) {
          isValidUser = true
          isAdmin = true
        }
      }

      if (!isValidUser) {
        return next(check.invalidUserPassword());
      }

      var m = new Model();
      m.getUserByEmail(email, function (error3, response3) {
        if (error3 || !response3.rows.length) {
          if (cfgData.idm.user_role || cfgData.idm.admin_role) {
            var newUser = {
              name: email,
              surname: email,
              password: Math.random().toString(36).slice(-11),
              email: email,
              superadmin: isAdmin,
              ldap: false
            }
            m.createUser(newUser, function (errorU, newUserId) {
              if (errorU) {
                return next(errorU);
              }
              newUser.id = newUserId;
              delete newUser.password;

              common.insertJwtToken(newUser, req.app.get('jwtTokenExpiration'), req.app.get('jwtTokenSecret'), function (error4, response4) {
                if (error4)
                  return next(error4);

                res.redirect(url.format({
                  pathname: req.query.state,
                  query: {'token': response4.token, 'expires' : response4.expires}
                }));
              });
            })
          }
          else {
            return next(check.invalidUserPassword());
          }
        }

        if (response3 && response3.rows && response3.rows.length) {

          var user = response3.rows[0];
          user.id = user.users_id;
          delete user.users_id;
          delete user.password;

          common.insertJwtToken(user, req.app.get('jwtTokenExpiration'), req.app.get('jwtTokenSecret'), function (error4, response4) {
            if (error4)
              return next(error4);

            res.redirect(url.format({
              pathname: req.query.state,
              query: {'token': response4.token, 'expires' : response4.expires}
            }));
          });

        }

      });

    });
  });
});

// Extended Graph for Oauth
router.get('/user/graph_oauth', check.checkToken, function(req, res, next) {
  graph.getUserGraph(res.user.id,function(err,data) {
    if (err)
      return next(err);
    res.json({
      graph: data,
      user: res.user
    });
  });
});

module.exports = router;
