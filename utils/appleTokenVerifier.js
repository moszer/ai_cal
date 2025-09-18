// utils/appleTokenVerifier.js
import jwt from 'jsonwebtoken';
import axios from 'axios';
import jwkToPem from 'jwk-to-pem';
import logger from './logger.js';

/**
 * Verify an Apple ID token
 * @param {string} identityToken - The identity token from Apple
 * @returns {Promise<Object>} - The payload from the verified token
 */
const verifyAppleIdToken = async (identityToken) => {
  try {
    // Log what we're trying to verify
    logger.info(`Attempting to verify Apple ID token`);
    
    // Fetch Apple's public keys
    const response = await axios.get('https://appleid.apple.com/auth/keys');
    const keys = response.data.keys;
    
    if (!keys || keys.length === 0) {
      logger.error('No Apple public keys available');
      throw new Error('No Apple public keys available');
    }
    
    // Decode the token header (without verification) to get the key ID
    const tokenParts = identityToken.split('.');
    if (tokenParts.length !== 3) {
      logger.error('Invalid Apple ID token format');
      throw new Error('Invalid token format');
    }
    
    // Base64 decode the header
    let header;
    try {
      // Make sure we handle URL-safe base64 by replacing characters
      const base64 = tokenParts[0].replace(/-/g, '+').replace(/_/g, '/');
      const headerJson = Buffer.from(base64, 'base64').toString();
      header = JSON.parse(headerJson);
    } catch (error) {
      logger.error(`Failed to decode token header: ${error.message}`);
      throw new Error('Invalid token header');
    }
    
    // Find the matching key by key ID
    const matchingKey = keys.find(key => key.kid === header.kid);
    if (!matchingKey) {
      logger.error(`No matching Apple public key found for kid: ${header.kid}`);
      throw new Error('No matching Apple public key found');
    }
    
    // Convert JWK to PEM format
    const pem = jwkToPem(matchingKey);
    
    // Get client ID safely
    const appleClientId = process.env.APPLE_CLIENT_ID || 'com.aicalorie.app'; // Default to app bundle ID
    
    // Verify the token
    const payload = jwt.verify(identityToken, pem, {
      algorithms: ['RS256'],
      // For Apple ID tokens, the audience (aud) should match your Apple client ID
      // This is typically your app's bundle ID
      audience: appleClientId,
      issuer: 'https://appleid.apple.com'
    });
    
    logger.info(`Successfully verified Apple token for subject: ${payload.sub || 'unknown'}`);
    
    // Extract and return the user information
    return {
      sub: payload.sub || '', // Apple's unique user ID
      email: payload.email || '',
      email_verified: payload.email_verified === true,
      name: '', // Apple doesn't provide name in the token, it's provided separately
    };
  } catch (error) {
    // More robust error handling
    logger.error(`Apple token verification error: ${error.message || 'Unknown error'}`);
    
    // Safely handle different error types
    if (error.response) {
      try {
        logger.error(`Response status: ${error.response.status}`);
        logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
      } catch (e) {
        logger.error('Error logging response details');
      }
    } else if (error.request) {
      logger.error('No response received from Apple');
    }
    
    throw new Error('Failed to verify Apple token');
  }
};

export default verifyAppleIdToken;
