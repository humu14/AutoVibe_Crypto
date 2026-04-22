import mongoose from "mongoose";

const sessionSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User"
  },
  token: {
    type: String,
    required: true
  },
  fingerprint: {
    type: String,
    required: true
  },
  ipAddress: {
    type: String,
    default: ''
  },
  userAgent: {
    type: String,
    default: ''
  },
  isValid: {
    type: Boolean,
    default: true
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// Auto-expire sessions using MongoDB TTL index
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
// Quick lookups by token
sessionSchema.index({ token: 1 });
// Quick lookups by user
sessionSchema.index({ userId: 1 });

const Session = mongoose.model("Session", sessionSchema);

export default Session;
