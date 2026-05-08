import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    // rsa ciphertext
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    // email hash
    emailHash: {
        type: String,
        required: true,
        unique: true
    },
    // rsa ciphertext
    phone: {
        type: String,
        default: ''
    },
    // password hash
    password: {
        type: String,
        required: true
    },
    // role
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    // legacy field
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
    // 2fa
    twoFactorEnabled: {
        type: Boolean,
        default: true  // enabled by default
    },
    // hmac
    dataHmac: {
        type: String,
        default: ''
    },
    // key version
    encryptionKeyVersion: {
        type: Number,
        default: 1
    }
}, {
    timestamps: true
});

// bcrypt hook removed
// password hash is in controller

const User = mongoose.model("User", userSchema);

export default User;