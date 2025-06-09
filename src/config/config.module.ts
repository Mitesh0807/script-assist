import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { validationSchema } from './config.schema';
import { appConfig, databaseConfig, jwtConfig, redisConfig, cacheConfig } from './configuration';
import bullConfig from './bull.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: `.env.${process.env.NODE_ENV || 'development'}`,
      validationSchema,
      load: [appConfig, databaseConfig, jwtConfig, redisConfig, cacheConfig, bullConfig],
    }),
  ],
})
export class AppConfigModule {}
