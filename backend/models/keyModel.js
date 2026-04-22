import mongoose from "mongoose";

const keySchema = mongoose.Schema({
  keyId: {
    type: String,
    required: true,
    unique: true
  },
  algorithm: {
    type: String,
    required: true,
    enum: ['RSA', 'ECC']
  },
  purpose: {
    type: String,
    required: true,
    enum: ['USER_DATA', 'PRODUCT_DATA', 'SESSION_SIGNING', 'REVIEW_DATA', 'ORDER_DATA', 'POST_DATA']
  },
  publicKey: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  privateKey: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  status: {
    type: String,
    required: true,
    enum: ['ACTIVE', 'ROTATED', 'REVOKED'],
    default: 'ACTIVE'
  },
  version: {
    type: Number,
    required: true,
    default: 1
  },
  rotatedAt: {
    type: Date,
    default: null
  },
  expiresAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Index for quick lookups
keySchema.index({ algorithm: 1, purpose: 1, status: 1 });

const Key = mongoose.model("Key", keySchema);

export default Key;
