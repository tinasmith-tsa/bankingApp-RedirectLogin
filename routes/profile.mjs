import express from 'express';
import { getOktaUserProfile, updateOktaUserProfile, isOktaApiAvailable } from '../services/oktaService.mjs';
import { getUserPreferences, createUserPreferences, updateUserPreferences } from '../database/db.mjs';

const router = express.Router();

// Re-authentication timeout (5 minutes)
const REAUTH_TIMEOUT = 5 * 60 * 1000;

/**
 * Middleware to ensure user is logged in
 */
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

/**
 * Middleware to ensure user has recently re-authenticated
 * Required for sensitive operations like profile editing
 */
function ensureRecentAuth(req, res, next) {
  const recentlyAuthenticated = req.session.recentlyAuthenticated;
  const now = Date.now();

  if (recentlyAuthenticated && (now - recentlyAuthenticated) < REAUTH_TIMEOUT) {
    // User has recently re-authenticated
    return next();
  }

  // Require re-authentication
  console.log('Re-authentication required for profile edit');
  res.redirect('/reauth');
}

/**
 * Helper to extract user email from passport user object
 */
function getUserEmail(user) {
  return user.emails?.[0]?.value ||
         user.email ||
         user._json?.email ||
         user.preferred_username ||
         user.username;
}

/**
 * GET /profile - Display profile page
 */
router.get('/', ensureLoggedIn, async (req, res) => {
  try {
    const userId = req.user.id;
    const email = getUserEmail(req.user);

    // Ensure user preferences exist
    if (userId && email) {
      createUserPreferences(userId, email);
    }

    // Get local preferences
    const preferences = userId ? getUserPreferences(userId) || {} : {};

    res.render('profile', {
      authenticated: req.isAuthenticated(),
      user: req.user,
      preferences,
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Profile page error:', error);
    res.render('profile', {
      authenticated: req.isAuthenticated(),
      user: req.user,
      preferences: {},
      error: 'Unable to load preferences'
    });
  }
});

/**
 * GET /profile/edit - Display edit form (requires recent re-authentication)
 */
router.get('/edit', ensureLoggedIn, ensureRecentAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const email = getUserEmail(req.user);

    // Get current Okta profile (for editable fields)
    let oktaProfile = {};
    if (isOktaApiAvailable() && userId) {
      try {
        oktaProfile = await getOktaUserProfile(userId);
      } catch (e) {
        console.error('Could not fetch Okta profile:', e.message);
      }
    }

    // Ensure user preferences exist
    if (userId && email) {
      createUserPreferences(userId, email);
    }

    // Get local preferences
    const preferences = userId ? getUserPreferences(userId) || {} : {};

    res.render('profile-edit', {
      authenticated: req.isAuthenticated(),
      user: req.user,
      oktaProfile,
      preferences,
      oktaApiAvailable: isOktaApiAvailable(),
      error: req.query.error
    });
  } catch (error) {
    console.error('Profile edit page error:', error);
    res.redirect('/profile?error=load_failed');
  }
});

/**
 * POST /profile/okta - Update Okta profile (requires recent re-authentication)
 */
router.post('/okta', ensureLoggedIn, ensureRecentAuth, async (req, res) => {
  try {
    // Try multiple ways to get the Okta user ID
    const userId = req.user.id ||
                   (req.user._json && req.user._json.sub) ||
                   req.user.sub;

    console.log('Attempting Okta profile update for user:', userId);
    console.log('User object keys:', Object.keys(req.user));

    const { firstName, lastName, mobilePhone } = req.body;

    // Validate input
    if (!firstName || !lastName) {
      return res.redirect('/profile/edit?error=name_required');
    }

    // Validate phone format (optional field)
    if (mobilePhone && !/^[\d\s\-\+\(\)]*$/.test(mobilePhone)) {
      return res.redirect('/profile/edit?error=invalid_phone');
    }

    if (!isOktaApiAvailable()) {
      console.log('Okta API not available');
      return res.redirect('/profile/edit?error=okta_not_configured');
    }

    if (!userId) {
      console.log('No user ID found in session');
      return res.redirect('/profile/edit?error=no_user_id');
    }

    // Update Okta profile
    await updateOktaUserProfile(userId, {
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      displayName: `${firstName.trim()} ${lastName.trim()}`,
      mobilePhone: mobilePhone ? mobilePhone.trim() : null
    });

    res.redirect('/profile?success=okta_updated');
  } catch (error) {
    console.error('Okta update error:', error.message);
    console.error('Full error:', error);
    res.redirect('/profile/edit?error=okta_update_failed');
  }
});

/**
 * POST /profile/preferences - Update local preferences (requires recent re-authentication)
 */
router.post('/preferences', ensureLoggedIn, ensureRecentAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    if (!userId) {
      return res.redirect('/profile/edit?error=no_user_id');
    }

    // Parse checkbox values (unchecked boxes don't send values)
    const preferences = {
      email_notifications: req.body.email_notifications === 'on' ? 1 : 0,
      sms_notifications: req.body.sms_notifications === 'on' ? 1 : 0,
      push_notifications: req.body.push_notifications === 'on' ? 1 : 0,
      transaction_alerts: req.body.transaction_alerts === 'on' ? 1 : 0,
      marketing_emails: req.body.marketing_emails === 'on' ? 1 : 0,
      theme: req.body.theme || 'light',
      language: req.body.language || 'en',
      currency_display: req.body.currency_display || 'USD',
      date_format: req.body.date_format || 'MM/DD/YYYY'
    };

    updateUserPreferences(userId, preferences);

    res.redirect('/profile?success=preferences_updated');
  } catch (error) {
    console.error('Preferences update error:', error);
    res.redirect('/profile/edit?error=preferences_update_failed');
  }
});

export default router;
