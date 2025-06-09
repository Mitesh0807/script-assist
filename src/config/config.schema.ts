import * as Joi from 'joi';

export const validationSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),

  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().required(),
  DB_USERNAME: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  DB_DATABASE: Joi.string().required(),

  JWT_SECRET: Joi.string().required(),
  JWT_EXPIRATION: Joi.string().required().default('1d'),

  REDIS_HOST: Joi.string().required(),
  REDIS_PORT: Joi.number().required(),

  CACHE_MAX_MEMORY_MB: Joi.number().default(100),
  CACHE_DEFAULT_TTL: Joi.number().default(300), // seconds
  CACHE_CLEANUP_INTERVAL: Joi.number().default(60000), // milliseconds
  CACHE_NAMESPACE: Joi.string().default('app'),
  CACHE_DISTRIBUTED: Joi.boolean().default(false),
});
