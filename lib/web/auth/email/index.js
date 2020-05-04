'use strict'

const Router = require('express').Router
const passport = require('passport')
const validator = require('validator')
const LocalStrategy = require('passport-local').Strategy
const config = require('../../../config')
const models = require('../../../models')
const logger = require('../../../logger')
const { urlencodedParser } = require('../../utils')
const errors = require('../../../errors')
const request = require('request')

let emailAuth = module.exports = Router()

passport.use(new LocalStrategy({
  usernameField: 'email'
}, function(username, password, done) {
  request({
    url: config["4labUrl"],
    method: "post",
    body: {
      username,
      password,
    },
    json: true,
  }, (err, res) => {
    if(err) {
      console.error(err);
      return done(err, false);
    }
    if(!res) {
      console.log("Res is empty but shouldn't (error was also empty).");
      return done(null, false);
    }

    if(res.statusCode !== 200) {
      return done(err || null, false);
    }

    const user = models.User.findOrCreate({
      where: {
        profileid: username,
      },
    })

    return done(null, user);
  });
}))

emailAuth.post('/login', urlencodedParser, function (req, res, next) {
  if (!req.body.email || !req.body.password) return errors.errorBadRequest(res)

  passport.authenticate('local', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/',
    failureFlash: 'Invalid email or password.'
  })(req, res, next)
})
