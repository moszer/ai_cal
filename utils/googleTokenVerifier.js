// utils/googleTokenVerifier.js
import axios from 'axios';
import logger from './logger.js';

/**
 * Verify a Google ID token
 * @param {string} idToken - The ID token to verify
 * @returns {Promise<Object>} - The payload from the verified token
 */
const verifyGoogleIdToken = async (idToken) => {
  try {
    // Log what we're trying to verify
    logger.info(`Attempting to verify Google ID token`);
    
    // Google's token info endpoint
    const response = await axios.get('https://oauth2.googleapis.com/tokeninfo', {
      params: { id_token: idToken }
    });
    
    // Get the token audience
    const tokenAudience = response.data.aud || '';
    logger.info(`Token has audience: ${tokenAudience}`);
    
    // Get client IDs safely
    const webClientId = process.env.GOOGLE_CLIENT_ID || '';
    const iosClientId = process.env.GOOGLE_IOS_CLIENT_ID || '';
    
    // Check audience against both client IDs
    if (tokenAudience !== webClientId && tokenAudience !== iosClientId) {
      // Safely log the first few characters of each ID to avoid logging entire credentials
      const webIdPrefix = webClientId ? webClientId.substring(0, 6) + '...' : 'not set';
      const iosIdPrefix = iosClientId ? iosClientId.substring(0, 6) + '...' : 'not set';
      
      logger.error(`Token audience mismatch: ${tokenAudience.substring(0, 6)}... does not match web (${webIdPrefix}) or iOS (${iosIdPrefix})`);
      throw new Error('Token audience mismatch');
    }
    
    logger.info(`Successfully verified Google token for email: ${response.data.email || 'unknown'}`);
    
    return {
      sub: response.data.sub || '',
      email: response.data.email || '',
      email_verified: response.data.email_verified === 'true',
      name: response.data.name || '',
    };
  } catch (error) {
    // More robust error handling
    logger.error(`Google token verification error: ${error.message || 'Unknown error'}`);
    
    // Safely handle different error types
    if (error.response) {
      try {
        logger.error(`Response status: ${error.response.status}`);
        logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
      } catch (e) {
        logger.error('Error logging response details');
      }
    } else if (error.request) {
      logger.error('No response received from Google');
    }
    
    throw new Error('Failed to verify Google token');
  }
};

export default verifyGoogleIdToken;
