/** two-factor controller */

import asyncHandler from 'express-async-handler';
import OTP from '../models/otpModel.js';
import { sha256 } from '../crypto/sha256.js';

const includeOtpForDev = process.env.NODE_ENV !== 'production';

/** generate otp code */
function generateOTPCode() {
  const seed = `${Date.now()}|${Math.random()}|${process.pid}|${Math.random()}`;
  const digest = sha256(seed);
  const numeric = parseInt(digest.slice(0, 12), 16);
  return String((numeric % 900000) + 100000);
}

/** create otp */
async function createOTP(userId) {
  // clear old otps
  await OTP.updateMany(
    { userId, verified: false },
    { verified: true } // mark old ones used
  );

  const code = generateOTPCode();
  const codeHash = sha256(code); // store hash
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5m

  await OTP.create({
    userId,
    codeHash,
    expiresAt,
    attempts: 0,
    maxAttempts: 5,
    verified: false
  });

  return { code, expiresAt };
}

/** verify otp code */
async function verifyOTPCode(userId, code) {
  const otp = await OTP.findOne({
    userId,
    verified: false,
    expiresAt: { $gt: new Date() }
  }).sort({ createdAt: -1 });

  if (!otp) {
    return { valid: false, error: 'No valid OTP found. Please request a new one.' };
  }

  // check attempt limit
  if (otp.attempts >= otp.maxAttempts) {
    otp.verified = true; // invalidate
    await otp.save();
    return { valid: false, error: 'Too many attempts. Please request a new OTP.' };
  }

  // increment attempts
  otp.attempts += 1;

  // verify hash
  const codeHash = sha256(code);
  if (codeHash !== otp.codeHash) {
    await otp.save();
    return { 
      valid: false, 
      error: `Invalid OTP. ${otp.maxAttempts - otp.attempts} attempts remaining.` 
    };
  }

  // mark verified
  otp.verified = true;
  await otp.save();

  return { valid: true };
}

/** verify otp api */
const verifyOTP = asyncHandler(async (req, res) => {
  const { userId, otpCode } = req.body;

  if (!userId || !otpCode) {
    res.status(400);
    throw new Error('User ID and OTP code are required');
  }

  const result = await verifyOTPCode(userId, otpCode);

  if (!result.valid) {
    res.status(401);
    throw new Error(result.error);
  }

  res.status(200).json({ verified: true, message: 'OTP verified successfully' });
});

/** resend otp api */
const resendOTP = asyncHandler(async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    res.status(400);
    throw new Error('User ID is required');
  }

  const { code, expiresAt } = await createOTP(userId);

  const response = {
    message: 'OTP sent successfully',
    expiresAt
  };

  if (includeOtpForDev) {
    response.otp = code;
  }

  res.status(200).json(response);
});

export { createOTP, verifyOTPCode, verifyOTP, resendOTP, generateOTPCode };
