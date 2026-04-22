# AutoVibe Crypto

AutoVibe Crypto is a full-stack e-commerce platform with a custom cryptography layer implemented from scratch.

The project combines:
- Node.js + Express backend
- React + Vite frontend
- MongoDB database
- Custom RSA, ECC, SHA-256, HMAC, and password hashing implementations
- Session-based authentication with custom RSA-signed tokens
- Two-factor authentication (OTP)

## Features

- Product catalog, categories, filters, search
- Cart, checkout, payment, order management
- Favorites and user profiles
- Admin dashboards for users, products, orders, reviews, sales, and key management
- Public and private posts
- End-to-end encrypted sensitive data at rest (users, orders, products, reviews, posts)
- HMAC integrity checks on critical records
- Global loading overlay during network activity in the frontend

## Repository Structure

- backend: Express API, crypto modules, controllers, models, middleware, routes
- frontend: React app, Redux Toolkit + RTK Query slices, screens, reusable components
- uploads: Uploaded files/images

## Tech Stack

### Backend

- express
- mongoose
- cookie-parser
- express-async-handler
- multer

### Frontend

- react
- react-router-dom
- @reduxjs/toolkit / RTK Query
- tailwindcss
- bootstrap
- material-ui

## Getting Started

## Prerequisites

- Node.js 18+
- npm 9+
- MongoDB (Atlas or local)

## Install

From project root:

```bash
npm install
npm install --prefix frontend
```

## Run Development

### Run backend + frontend together

```bash
npm run dev
```

### Run backend only

```bash
npm start
```

### Run frontend only

```bash
npm run client
```

## Environment Variables

Create a .env file in the project root.

Recommended variables:

```env
NODE_ENV=development
PORT=5000
MONGO_URI=your_mongodb_connection_string
PAYPAL_CLIENT_ID=your_paypal_client_id

# Key encryption key-pair for protecting private keys at rest
KEY_ENCRYPTION_PUBLIC_N=...
KEY_ENCRYPTION_PUBLIC_E=...
KEY_ENCRYPTION_PRIVATE_N=...
KEY_ENCRYPTION_PRIVATE_D=...

# HMAC secret for integrity checks
HMAC_SECRET=replace_with_long_random_secret
```

Important:
- If KEY_ENCRYPTION_* variables are not set, the backend generates a runtime-only key pair.
- Runtime-only mode means encrypted private keys may become undecryptable after restart, so set KEY_ENCRYPTION_* for persistent environments.

## API Overview

Main route groups:
- /api/users
- /api/products
- /api/orders
- /api/reviews
- /api/posts
- /api/keys (admin)

## Cryptography: Where It Is Applied

This section explicitly maps cryptographic operations to backend code paths and frontend flows.

## Backend Cryptography Modules

Core implementations live in:
- backend/crypto/rsa.js
- backend/crypto/ecc.js
- backend/crypto/sha256.js
- backend/crypto/hmac.js
- backend/crypto/passwordHash.js
- backend/crypto/keyManager.js

## 1) RSA Encryption

Used for:
- User sensitive fields (name, email, phone)
- Order shipping address fields
- Order payer email in paymentResult

Where:
- backend/controllers/userController.js
  - encryptUserData
  - decryptUserData
  - register
  - getUserProfile
  - updateUserProfile
- backend/controllers/orderController.js
  - encryptOrderData
  - decryptOrderData
  - addOrderItems
  - updateOrderToPaid

## 2) ECC Encryption (EC-ElGamal)

Used for:
- Product text fields (name, description, brand)
- Review comments
- Post title/content

Where:
- backend/controllers/productController.js
  - encryptProductData
  - decryptProductData
  - createProduct
  - updateProduct
  - getProduct / getProductById / filter/search paths
- backend/controllers/reviewController.js
  - encryptReviewData
  - decryptReviewData
  - createReview
  - getReview / getAllReviews
- backend/controllers/postController.js
  - encryptPostData
  - decryptPostData
  - createPost
  - updatePost
  - getMyPosts / getPublicPosts / getPostById

## 3) RSA-Signed Session Tokens

Used for:
- Authentication token signing and verification
- Session hijack protection via fingerprint checks

Where:
- backend/utils/generateToken.js
  - generateToken: builds header.payload.signature and signs with RSA private key
  - session token hash storage using SHA-256
- backend/middleware/authMiddleware.js
  - protect: verifies RSA signature with current/older key versions
  - verifies token expiry
  - validates request fingerprint against stored session fingerprint

## 4) SHA-256

Used for:
- Email hashing for user lookup (emailHash)
- OTP code hashing before storage
- Token hash storage in sessions
- Fingerprint generation

Where:
- backend/controllers/userController.js
- backend/controllers/twoFactorController.js
- backend/utils/generateToken.js
- backend/middleware/authMiddleware.js

## 5) Password Hashing

Used for:
- Password storage and verification

Where:
- backend/controllers/userController.js
  - register: hashPassword
  - authUser: verifyPassword
- backend/crypto/passwordHash.js provides the full implementation with salt + iterative SHA-256

## 6) HMAC Integrity Protection

Used for tamper detection on persisted records:
- Users
- Products
- Orders
- Reviews
- Posts

Where:
- backend/controllers/userController.js
  - computeUserHmac
  - verifyUserIntegrity
- backend/controllers/productController.js
  - computeProductHmac
  - verifyProductIntegrity
- backend/controllers/orderController.js
  - computeOrderHmac
- backend/controllers/reviewController.js
  - computeReviewHmac
- backend/controllers/postController.js
  - computePostHmac
  - verifyPostIntegrity

## 7) Key Lifecycle Management

Used for:
- Startup key generation (RSA + ECC by purpose)
- Key rotation and revocation
- Active/versioned key lookup for backward decryption
- At-rest encryption of stored private keys

Where:
- backend/crypto/keyManager.js
- backend/controllers/keyController.js
- backend/routes/keyRoute.js

Current key purposes:
- RSA: USER_DATA, ORDER_DATA, SESSION_SIGNING
- ECC: PRODUCT_DATA, REVIEW_DATA, POST_DATA

## Frontend: Where Crypto Is Involved

Frontend does not perform cryptographic math locally. It triggers cryptography-enabled backend operations and consumes decrypted responses.

## Auth + 2FA flow

- Login/register/OTP endpoints are called from:
  - frontend/src/slices/userApiSlice.js
  - frontend/src/screens/TwoFactorScreen.jsx
- Backend performs:
  - password hash verification
  - OTP hash verification
  - RSA token signing

## Profile flow

- frontend/src/screens/ProfileScreen.jsx calls update profile endpoints.
- Backend encrypts/decrypts profile fields and verifies HMAC.

## Product/review/post flows

- frontend/src/slices/productsApiSlice.js
- frontend/src/slices/reviewApiSlice.js
- frontend/src/slices/postApiSlice.js
- frontend/src/screens/* and frontend/src/components/* consume these endpoints.
- Backend encrypts at write-time and decrypts at read-time using ECC and verifies HMAC.

## Order flow

- frontend/src/slices/ordersApiSlice.js
- order/cart/checkout screens call order endpoints.
- Backend encrypts shipping/payment-sensitive fields with RSA and computes HMAC.

## Admin key-management flow

- frontend/src/screens/admin/KeyManagementScreen.jsx
- Calls key APIs:
  - GET /api/keys
  - GET /api/keys/status
  - POST /api/keys/rotate/:keyId
  - POST /api/keys/revoke/:keyId

## Global Loading Animation

A global loading overlay now appears when network requests are in-flight.

Implementation:
- frontend/src/slices/networkLoadingSlice.js
- frontend/src/utils/installGlobalFetchTracker.js
- frontend/src/components/GlobalLoadingOverlay.jsx
- frontend/src/main.jsx (tracker installation)
- frontend/src/App.jsx (overlay render)

Behavior:
- Any fetch call increments pending request count on start and decrements on completion.
- Overlay is shown for pending operations and hidden when all requests complete.

## Security Notes

- Replace hardcoded DB connection string in backend/config/db.js with process.env.MONGO_URI for production safety.
- Never commit real credentials or private key values into git.
- Set strong HMAC_SECRET and persistent KEY_ENCRYPTION_* values in production.
- Use HTTPS in production to protect cookie transport.

## Troubleshooting

## Port already in use

If you see EADDRINUSE on port 5000, stop the existing Node process using that port, then restart.

## Key decryption warnings on startup

If KEY_ENCRYPTION_* variables are missing or changed, existing encrypted private keys may fail to decrypt.
Use stable KEY_ENCRYPTION_* values to avoid regeneration and preserve key continuity.

## Scripts

Root package scripts:

```json
{
  "start": "node backend/server.js",
  "server": "nodemon backend/server.js",
  "client": "npm run dev --prefix frontend",
  "dev": "concurrently \"npm start\" \"npm run client\""
}
```

## License

ISC
