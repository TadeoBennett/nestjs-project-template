// Load JWT secret from environment. In production we require it to be set.
const envSecret = process.env.JWT_SECRET;
if (!envSecret && process.env.NODE_ENV === 'production') {
  throw new Error('JWT_SECRET environment variable must be set in production');
}

export const jwtConstants = {
  // Use a short-lived development fallback so local development works without env setup.
  // IMPORTANT: change this by setting JWT_SECRET in your environment for production.
  secret: envSecret ?? 'dev_jwt_secret_change_me',
  accessTtl: '10m',
  refreshTtl: '30d',
  defaultTtl: '1d',
};
