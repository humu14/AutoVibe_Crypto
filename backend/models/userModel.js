import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    // Encrypted fields (RSA encrypted - stored as ciphertext)
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    // Deterministic hash of email for lookups (SHA-256)
    emailHash: {
        type: String,
        required: true,
        unique: true
    },
    // Phone number (RSA encrypted)
    phone: {
        type: String,
        default: ''
    },
    // Password (custom SHA-256 hash with salt: $iterations$salt$hash)
    password: {
        type: String,
        required: true
    },
    // Role-based access control
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    // Legacy field - kept for backward compatibility
    isAdmin: {
        type: Boolean,
        required: true,
        default: false
    },
    isArtist: {
        type: Boolean,
        default: false
    },
    artistId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Artist"
    },
    favoriteProducts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product"
    }],
    points: {
        type: Number,
        default: 0
    },
    membership: {
        type: { type: String },
        expires: { type: Date },
        discount: { type: Number, default: 0 }
    },
    // Two-factor authentication
    twoFactorEnabled: {
        type: Boolean,
        default: true  // Enabled by default per requirement
    },
    // Data integrity - HMAC of sensitive fields
    dataHmac: {
        type: String,
        default: ''
    },
    // Tracks which key version encrypted this record
    encryptionKeyVersion: {
        type: Number,
        default: 1
    }
}, {
    timestamps: true
});

// NOTE: bcrypt pre-save hook removed — password hashing is handled in the controller
// using our custom passwordHash module

const User = mongoose.model("User", userSchema);

export default User;