/** rbac middleware */

/** role guard */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401);
      throw new Error('Authentication required');
    }

    // keep legacy admin flag
    const userRole = req.user.isAdmin ? 'admin' : (req.user.role || 'user');

    if (!roles.includes(userRole)) {
      res.status(403);
      throw new Error(`Access denied. Required role: ${roles.join(' or ')}. Your role: ${userRole}`);
    }

    next();
  };
};

/** admin only */
const adminOnly = requireRole('admin');

/** authenticated */
const authenticated = requireRole('admin', 'user');

export { requireRole, adminOnly, authenticated };
