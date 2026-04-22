import mongoose from "mongoose";

const otpSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User"
  },
  codeHash: {
    type: String,
    required: true
  },
  attempts: {
    type: Number,
    default: 0
  },
  maxAttempts: {
    type: Number,
    default: 5
  },
  verified: {
    type: Boolean,
    default: false
  },
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// Auto-expire OTPs using MongoDB TTL index
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
// Quick lookups by user
otpSchema.index({ userId: 1 });

const OTP = mongoose.model("OTP", otpSchema);

export default OTP;
