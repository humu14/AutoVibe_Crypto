/**
 * Role-Based Access Control (RBAC) Middleware
 * Defines separate privileges for administrators and regular users
 */

/**
 * Middleware factory that checks if user has one of the required roles
 * @param  {...string} roles - Allowed roles (e.g., 'admin', 'user')
 * @returns {Function} Express middleware
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401);
      throw new Error('Authentication required');
    }

    // Prefer legacy isAdmin flag so admin access keeps working for older users
    // whose role field may still be "user".
    const userRole = req.user.isAdmin ? 'admin' : (req.user.role || 'user');

    if (!roles.includes(userRole)) {
      res.status(403);
      throw new Error(`Access denied. Required role: ${roles.join(' or ')}. Your role: ${userRole}`);
    }

    next();
  };
};

/**
 * Admin-only middleware (shorthand)
 */
const adminOnly = requireRole('admin');

/**
 * Authenticated user middleware (any role)
 */
const authenticated = requireRole('admin', 'user');

export { requireRole, adminOnly, authenticated };
