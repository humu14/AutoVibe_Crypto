import mongoose from "mongoose";

const reviewSchema = mongoose.Schema({
    rating: {
        type: Number,
        required: true,
    },
    // ecc ciphertext
    comment: {
        type: String,
        required: true,
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref:'User'
    },
    product: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref:'Product'
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
},{
    timestamps: true
});

const Review = mongoose.model("Review", reviewSchema);

export default Review;