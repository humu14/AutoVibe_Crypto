import mongoose from "mongoose";

const reviewSchema = mongoose.Schema({
    rating: {
        type: Number,
        required: true,
    },
    // Encrypted with ECC
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
    // Data integrity - HMAC of review fields
    dataHmac: {
        type: String,
        default: ''
    },
    // Tracks which ECC key version encrypted this record
    encryptionKeyVersion: {
        type: Number,
        default: 1
    }
},{
    timestamps: true
});

const Review = mongoose.model("Review", reviewSchema);

export default Review;