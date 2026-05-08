import asyncHandler from 'express-async-handler';
import Post from '../models/postModel.js';
import { getActiveKey, getKeyByVersion, getHmacSecret } from '../crypto/keyManager.js';
import { hmac, verifyHmac } from '../crypto/hmac.js';
import * as eccCrypto from '../crypto/ecc.js';

function normalizeVisibility(value) {
  const normalized = String(value || 'private').trim().toLowerCase();
  return normalized.includes('public') ? 'public' : 'private';
}

function isOwnerOrAdmin(req, ownerId) {
  if (!req.user) return false;
  if (req.user.role === 'admin' || req.user.isAdmin) return true;
  return String(req.user._id) === String(ownerId);
}

function computePostHmac(post) {
  const secret = getHmacSecret();
  const fields = [
    String(post.user || ''),
    post.title || '',
    post.content || '',
    post.visibility || 'private'
  ].join('|');
  return hmac(secret, fields);
}

function verifyPostIntegrity(post) {
  if (!post.dataHmac) return true;
  const secret = getHmacSecret();
  const fields = [
    String(post.user || ''),
    post.title || '',
    post.content || '',
    post.visibility || 'private'
  ].join('|');
  return verifyHmac(secret, fields, post.dataHmac);
}

async function encryptPostData(data) {
  const key = await getActiveKey('ECC', 'POST_DATA');
  const encrypted = { ...data };

  if (data.title) encrypted.title = eccCrypto.encryptString(data.title, key.publicKey);
  if (data.content) encrypted.content = eccCrypto.encryptString(data.content, key.publicKey);

  encrypted.encryptionKeyVersion = key.version;
  return encrypted;
}

async function decryptPostData(post) {
  try {
    let key;
    if (post.encryptionKeyVersion) {
      try {
        key = await getKeyByVersion('ECC', 'POST_DATA', post.encryptionKeyVersion);
      } catch {
        key = await getActiveKey('ECC', 'POST_DATA');
      }
    } else {
      key = await getActiveKey('ECC', 'POST_DATA');
    }

    const obj = post.toObject ? post.toObject() : { ...post };
    if (obj.title) obj.title = eccCrypto.decryptString(obj.title, key.privateKey);
    if (obj.content) obj.content = eccCrypto.decryptString(obj.content, key.privateKey);

    return obj;
  } catch (e) {
    console.error('Post decryption error:', e.message);
    const obj = post.toObject ? post.toObject() : { ...post };
    obj.title = '🔒 Unrecoverable Encrypted Title';
    obj.content = 'This post\'s content cannot be decrypted because its encryption key is no longer available (e.g., the key was revoked or lost due to a server restart without persistent key encryption).';
    return obj;
  }
}

const createPost = asyncHandler(async (req, res) => {
  const { title, content, visibility } = req.body;

  if (!title || !content) {
    res.status(400);
    throw new Error('Title and content are required');
  }

  const encrypted = await encryptPostData({ title, content });

  const normalizedVisibility = normalizeVisibility(visibility);

  const postData = {
    user: req.user._id,
    title: encrypted.title,
    content: encrypted.content,
    visibility: normalizedVisibility,
    encryptionKeyVersion: encrypted.encryptionKeyVersion
  };

  postData.dataHmac = computePostHmac(postData);

  const post = await Post.create(postData);
  const decrypted = await decryptPostData(post);

  res.status(201).json(decrypted);
});

const getMyPosts = asyncHandler(async (req, res) => {
  const queryText = (req.query.q || '').toString().trim().toLowerCase();
  const posts = await Post.find({ user: req.user._id }).sort({ createdAt: -1 });

  const decryptedPosts = [];
  for (const post of posts) {
    if (!verifyPostIntegrity(post)) {
      console.warn(`Post integrity check failed: ${post._id}`);
    }
    const decrypted = await decryptPostData(post);

    if (!queryText) {
      decryptedPosts.push(decrypted);
      continue;
    }

    const title = (decrypted.title || '').toLowerCase();
    const content = (decrypted.content || '').toLowerCase();
    if (title.includes(queryText) || content.includes(queryText)) {
      decryptedPosts.push(decrypted);
    }
  }

  res.status(200).json(decryptedPosts);
});

const getPostById = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    res.status(404);
    throw new Error('Post not found');
  }

  const isPublic = post.visibility === 'public';
  if (!isPublic && !isOwnerOrAdmin(req, post.user)) {
    res.status(403);
    throw new Error('Not authorized to view this post');
  }

  if (!verifyPostIntegrity(post)) {
    console.warn(`Post integrity check failed: ${post._id}`);
  }

  const decrypted = await decryptPostData(post);
  res.status(200).json(decrypted);
});

const updatePost = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    res.status(404);
    throw new Error('Post not found');
  }

  if (!isOwnerOrAdmin(req, post.user)) {
    res.status(403);
    throw new Error('Not authorized to update this post');
  }

  const key = await getActiveKey('ECC', 'POST_DATA');

  if (req.body.title) {
    post.title = eccCrypto.encryptString(req.body.title, key.publicKey);
  }

  if (req.body.content) {
    post.content = eccCrypto.encryptString(req.body.content, key.publicKey);
  }

  if (req.body.visibility !== undefined) {
    const normalizedVisibility = normalizeVisibility(req.body.visibility);
    post.visibility = normalizedVisibility;
  }

  post.encryptionKeyVersion = key.version;
  post.dataHmac = computePostHmac(post);

  const updated = await post.save();
  const decrypted = await decryptPostData(updated);

  res.status(200).json(decrypted);
});

const setPostVisibility = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    res.status(404);
    throw new Error('Post not found');
  }

  if (!isOwnerOrAdmin(req, post.user)) {
    res.status(403);
    throw new Error('Not authorized to update this post visibility');
  }

  post.visibility = normalizeVisibility(req.body.visibility);
  post.dataHmac = computePostHmac(post);

  const updated = await post.save();
  const decrypted = await decryptPostData(updated);

  res.status(200).json(decrypted);
});

const getAllPosts = asyncHandler(async (req, res) => {
  const posts = await Post.find({}).sort({ createdAt: -1 });

  const decryptedPosts = [];
  for (const post of posts) {
    if (!verifyPostIntegrity(post)) {
      console.warn(`Post integrity check failed: ${post._id}`);
    }
    decryptedPosts.push(await decryptPostData(post));
  }

  res.status(200).json(decryptedPosts);
});

const getPublicPosts = asyncHandler(async (req, res) => {
  const queryText = (req.query.q || '').toString().trim().toLowerCase();
  const posts = await Post.find({ visibility: { $regex: '^public$', $options: 'i' } }).sort({ createdAt: -1 });

  const decryptedPosts = [];
  for (const post of posts) {
    if (!verifyPostIntegrity(post)) {
      console.warn(`Post integrity check failed: ${post._id}`);
    }

    const decrypted = await decryptPostData(post);

    if (!queryText) {
      decryptedPosts.push(decrypted);
      continue;
    }

    const title = (decrypted.title || '').toLowerCase();
    const content = (decrypted.content || '').toLowerCase();
    if (title.includes(queryText) || content.includes(queryText)) {
      decryptedPosts.push(decrypted);
    }
  }

  res.status(200).json(decryptedPosts);
});

const deletePost = asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);

  if (!post) {
    res.status(404);
    throw new Error('Post not found');
  }

  if (!isOwnerOrAdmin(req, post.user)) {
    res.status(403);
    throw new Error('Not authorized to delete this post');
  }

  await post.deleteOne();
  res.status(200).json({ message: 'Post deleted successfully' });
});

export { createPost, getMyPosts, getPostById, updatePost, setPostVisibility, getAllPosts, getPublicPosts, deletePost };
