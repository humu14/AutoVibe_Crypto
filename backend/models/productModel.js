import mongoose from "mongoose";

const productSchema = mongoose.Schema({
    // Encrypted with ECC (stored as ciphertext)
    name: {
        type: String,
        required: true
    },
    brand: {
        type: String,
    },
    sku: {
        type: String,
        sparse: true
    },
    upc: {
        type: String,
        sparse: true
    },
    // Encrypted with ECC
    description: {
        type: String,
    },
    category: {
        type: String,
    },
    subcategory: {
        type: String,
    },
    compatibleVehicles: [{
        type: String,
    }],
    fitmentNotes: {
        type: String,
    },
    material: {
        type: String,
    },
    color: {
        type: String,
    },
    weightKg: {
        type: Number,
        default: 0
    },
    dimensionsCm: {
        length: { type: Number, default: 0 },
        width: { type: Number, default: 0 },
        height: { type: Number, default: 0 },
    },
    warrantyMonths: {
        type: Number,
        default: 0
    },
    price: {
        type: Number,
        default: 0,
        required: true,
    },
    countInStock: {
        type: Number,
        default: 0,
        required: true,
    },
    image: {
        type: String,
    },
    images: [{
        type: String,
    }],
    tags: [{ type: String }],
    numReviews: {
        type: Number,
        default: 0,
    },
    rating: {
        type: Number,
        default: 0,
        min: 0,
        max: 5
    },
    isFeatured: {
        type: Boolean,
        default: false,
    },
    // Data integrity - HMAC of product fields
    dataHmac: {
        type: String,
        default: ''
    },
    // Tracks which ECC key version encrypted this record
    encryptionKeyVersion: {
        type: Number,
        default: 1
    }
}, {
    timestamps: true
});

const Product = mongoose.model("Product", productSchema);

export default Product;
