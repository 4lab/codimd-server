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

let labAuth = module.exports = Router()

passport.use('4lab', new LocalStrategy(
  function(username, password, done) {

    request({
      url: config["4labUrl"],
      method: "post",
      body: {
        username,
        password,
      },
    }, (err, res) => {
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
  }
));

labAuth.post('/login', urlencodedParser, function (req, res, next) {
  if (!req.body.email || !req.body.password) return errors.errorBadRequest(res)
  if (!validator.isEmail(req.body.email)) return errors.errorBadRequest(res)
  passport.authenticate('4lab', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/',
    failureFlash: 'Invalid email or password.'
  })(req, res, next)
})
