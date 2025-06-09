import { registerAs } from '@nestjs/config';

export const DATABASE_CONFIG_TOKEN = 'database';
export const JWT_CONFIG_TOKEN = 'jwt';
export const REDIS_CONFIG_TOKEN = 'redis';
export const CACHE_CONFIG_TOKEN = 'cache';
export const APP_CONFIG_TOKEN = 'app';

export const appConfig = registerAs(APP_CONFIG_TOKEN, () => ({
  nodeEnv: process.env.NODE_ENV!,
  port: parseInt(process.env.PORT!, 10) || 3000,
}));

export const databaseConfig = registerAs(DATABASE_CONFIG_TOKEN, () => ({
  host: process.env.DB_HOST!,
  port: parseInt(process.env.DB_PORT!, 10),
  username: process.env.DB_USERNAME!,
  password: process.env.DB_PASSWORD!,
  database: process.env.DB_DATABASE!,
}));

export const jwtConfig = registerAs(JWT_CONFIG_TOKEN, () => ({
  secret: process.env.JWT_SECRET!,
  expiration: process.env.JWT_EXPIRATION!,
}));

export const redisConfig = registerAs(REDIS_CONFIG_TOKEN, () => ({
  host: process.env.REDIS_HOST!,
  port: parseInt(process.env.REDIS_PORT!, 10),
}));

export const cacheConfig = registerAs(CACHE_CONFIG_TOKEN, () => ({
  maxMemoryMB: parseInt(process.env.CACHE_MAX_MEMORY_MB!, 10),
  defaultTTL: parseInt(process.env.CACHE_DEFAULT_TTL!, 10),
  cleanupInterval: parseInt(process.env.CACHE_CLEANUP_INTERVAL!, 10),
  namespace: process.env.CACHE_NAMESPACE!,
  enableDistributed: process.env.CACHE_DISTRIBUTED === 'true',
  redisUrl: `redis://${process.env.REDIS_HOST!}:${process.env.REDIS_PORT!}`,
}));
