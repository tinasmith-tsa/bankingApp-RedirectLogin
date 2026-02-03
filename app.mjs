import express from 'express';
import createError from 'http-errors';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import session from 'express-session';
import passport from 'passport';
import qs from 'querystring';
import { Strategy } from 'passport-openidconnect';
import axios from 'axios';

// Import session store and universal logout
import { store, registerUserSession, unregisterUserSession } from './sessionStore.mjs';
import { universalLogoutRoute, universalLogoutAuth, initializeJwksClient } from './universalLogout.mjs';

// source and import environment variables
import dotenv from 'dotenv'

dotenv.config({ path: '.okta.env' })
const { ORG_URL, CLIENT_ID, CLIENT_SECRET, SESSION_SECRET, BASE_URL } = process.env;

// Base URL for callbacks (defaults to localhost for development)
const APP_BASE_URL = BASE_URL || 'http://localhost:3000';

// Universal Logout endpoint URL (used as JWT audience)
const REVOCATION_ENDPOINT = `${APP_BASE_URL}/api/global-token-revocation`;

import homeRoute from './routes/index.js';
import profileRouter from './routes/profile.mjs';
const app = express();

// view engine setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Use the shared session store for Universal Logout support
app.use(session({
  secret: SESSION_SECRET || 'CanYouLookTheOtherWay',
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Initialize JWKS client for Universal Logout JWT validation
initializeJwksClient(ORG_URL);

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
let logout_url, id_token;
const _base = ORG_URL.slice(-1) == '/' ? ORG_URL.slice(0, -1) : ORG_URL;

axios
  .get(`${_base}/.well-known/openid-configuration`)
  .then(res => {
    if (res.status == 200) {
      let { issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, end_session_endpoint } = res.data;
      logout_url = end_session_endpoint;

      // Set up passport - standard login
      passport.use('oidc', new Strategy({
        issuer,
        authorizationURL: authorization_endpoint,
        tokenURL: token_endpoint,
        userInfoURL: userinfo_endpoint,
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackURL: `${APP_BASE_URL}/authorization-code/callback`,
        scope: 'openid profile email',
      }, (issuer, profile, context, idToken, accessToken, params, done) => {
        console.log(`OIDC response: ${JSON.stringify({
          issuer, profile, context, idToken,
          accessToken, params
        }, null, 2)}\n*****`);
        id_token = idToken;
        return done(null, profile);
      }));

      // Set up passport - step-up re-authentication (forces login prompt)
      passport.use('oidc-reauth', new Strategy({
        issuer,
        authorizationURL: authorization_endpoint,
        tokenURL: token_endpoint,
        userInfoURL: userinfo_endpoint,
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        callbackURL: `${APP_BASE_URL}/authorization-code/callback-reauth`,
        scope: 'openid profile email',
        prompt: 'login',  // Force re-authentication
      }, (issuer, profile, context, idToken, accessToken, params, done) => {
        console.log('Re-authentication successful for:', profile.displayName);
        id_token = idToken;
        return done(null, profile);
      }));
    }
    else {
      console.error(`Unable to reach the well-known endpoint. Are you sure that the ORG_URL you provided (${ORG_URL}) is correct?`);
    }
  })
  .catch(error => {
    console.error(error);
  });

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});

function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect('/login')
}

// Middleware to check if session was terminated by Universal Logout
app.use((req, res, next) => {
  if (req.session && req.session.terminated) {
    req.logout((err) => {
      req.session.destroy();
      return res.redirect('/?logged_out=universal');
    });
  } else {
    next();
  }
});

app.use('/', homeRoute);

app.use('/login', passport.authenticate('oidc'));

app.use('/authorization-code/callback',
  // https://github.com/jaredhanson/passport/issues/458
  passport.authenticate('oidc', { failureMessage: true, failWithError: true }),
  (req, res) => {
    // Register the session for Universal Logout tracking
    if (req.user) {
      const email = req.user.emails?.[0]?.value ||
                   req.user.email ||
                   req.user._json?.email ||
                   req.user.preferred_username ||
                   req.user.username;
      if (email && req.sessionID) {
        registerUserSession(email, req.sessionID);
        console.log(`Session registered for user: ${email}, sessionID: ${req.sessionID}`);
      }
    }
    res.redirect('/profile');
  }
);

// Step-up re-authentication for sensitive operations
app.get('/reauth', ensureLoggedIn, passport.authenticate('oidc-reauth'));

// Callback for re-authentication
app.use('/authorization-code/callback-reauth',
  passport.authenticate('oidc-reauth', { failureMessage: true, failWithError: true }),
  (req, res) => {
    // Mark session as recently re-authenticated
    req.session.recentlyAuthenticated = Date.now();
    console.log('User re-authenticated, redirecting to profile edit');
    res.redirect('/profile/edit');
  }
);

// Profile routes (view, edit, update)
app.use('/profile', profileRouter);

app.post('/logout', (req, res, next) => {
  // Unregister the session from Universal Logout tracking
  if (req.user) {
    const email = req.user.emails?.[0]?.value ||
                 req.user.email ||
                 req.user._json?.email ||
                 req.user.preferred_username ||
                 req.user.username;
    if (email && req.sessionID) {
      unregisterUserSession(email, req.sessionID);
    }
  }

  req.logout(err => {
    if (err) { return next(err); }
    let params = {
      id_token_hint: id_token,
      post_logout_redirect_uri: `${APP_BASE_URL}/`
    }
    res.redirect(logout_url + '?' + qs.stringify(params));
  });
});

/**
 * Universal Logout API endpoints
 *
 * Okta JWT Authentication:
 * When Okta sends a Universal Logout request, it includes a JWT with:
 * - Header: { "typ": "global-token-revocation+jwt", "alg": "RS256" }
 * - Payload: { "jti", "iss", "sub", "aud", "exp", "nbf", "iat" }
 *
 * The JWT is signed with Okta's private key and can be validated using
 * the public keys from the JWKS endpoint.
 */

// Mount Universal Logout routes with JWT authentication
app.use('/api', universalLogoutAuth(ORG_URL, REVOCATION_ENDPOINT), universalLogoutRoute);

// Health check endpoint (no auth required)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'SecureBank Universal Logout',
    version: '2.0',
    supported_formats: ['email', 'iss_sub'],
    endpoints: {
      revocation: '/api/global-token-revocation',
      health: '/api/health'
    },
    timestamp: new Date().toISOString()
  });
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message + (err.code && ' (' + err.code + ')' || '') +
    (req.session.messages && ": " + req.session.messages.join("\n. ") || '');
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

// Log Universal Logout configuration on startup
console.log('\n============================================================');
console.log('SecureBank - Universal Logout v2.0 (Okta Specification)');
console.log('============================================================');
console.log('');
console.log('Endpoints:');
console.log('  POST /api/global-token-revocation  - Revoke user sessions');
console.log('  GET  /api/health                   - Health check');
console.log('');
console.log('Authentication:');
console.log('  Okta-signed JWT required');
console.log('  Header: { "typ": "global-token-revocation+jwt", "alg": "RS256" }');
console.log('  JWKS:   ' + _base + '/oauth2/v1/keys');
console.log('');
console.log('Subject Identifier Formats:');
console.log('  - email:   { "sub_id": { "format": "email", "email": "user@example.com" } }');
console.log('  - iss_sub: { "sub_id": { "format": "iss_sub", "iss": "...", "sub": "..." } }');
console.log('');
console.log('Response Codes:');
console.log('  204 - Success (sessions revoked)');
console.log('  400 - Malformed request');
console.log('  401 - Invalid authentication');
console.log('  404 - User not found');
console.log('  422 - Unable to revoke sessions');
console.log('============================================================\n');

export default app;
