import mongoose from 'mongoose';

const postSchema = mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'User'
    },
    // Encrypted with ECC
    title: {
      type: String,
      required: true
    },
    // Encrypted with ECC
    content: {
      type: String,
      required: true
    },
    visibility: {
      type: String,
      enum: ['public', 'private'],
      default: 'private'
    },
    dataHmac: {
      type: String,
      default: ''
    },
    encryptionKeyVersion: {
      type: Number,
      default: 1
    }
  },
  {
    timestamps: true
  }
);

postSchema.index({ user: 1, createdAt: -1 });

const Post = mongoose.model('Post', postSchema);

export default Post;
