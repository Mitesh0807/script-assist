import { registerAs } from '@nestjs/config';

export const BULL_CONFIG_TOKEN = 'bull';

export const bullConfig = registerAs(BULL_CONFIG_TOKEN, () => ({
  connection: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
  },
}));

export type BullConfig = ReturnType<typeof bullConfig>;
