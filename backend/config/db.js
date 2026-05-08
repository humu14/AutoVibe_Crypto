import mongoose from "mongoose";
import dotenv from 'dotenv';
dotenv.config();

const connectDB = async () => {
    try {
        let uri = process.env.MONGO_URI;
        if (!uri) throw new Error('MONGO_URI is not defined in environment variables');
        // Ensure database name "store" is always set even if URI omits it
        if (!uri.includes('/store')) {
            uri = uri.replace(/\/?(\?|$)/, '/store$1');
        }
        const conn = await mongoose.connect(uri);
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};

export default connectDB;