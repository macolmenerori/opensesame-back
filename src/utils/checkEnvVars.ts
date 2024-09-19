/* eslint-disable no-console */

const checkEnvVars = (): boolean => {
  const requiredEnvVars = [
    'NODE_ENV',
    'PORT',
    'DB_NAME',
    'DATABASE',
    'PASSWORD_HASH_DIFFICULTY',
    'JWT_SECRET',
    'JWT_EXPIRES_IN',
    'JWT_COOKIE_EXPIRES_IN',
    'RATELIMIT_MAXCONNECTIONS',
    'RATELIMIT_WINDOWMS',
    'CORS_WHITELIST'
  ];

  const missingEnvVars: string[] = [];

  requiredEnvVars.forEach((envVar) => {
    if (!process.env[envVar]) {
      missingEnvVars.push(envVar);
    }
  });

  if (missingEnvVars.length > 0) {
    console.error(`Missing environment variables: ${missingEnvVars.join(', ')}`);
    return true;
  } else {
    return false;
  }
};

export default checkEnvVars;
