import { Module, Global, DynamicModule } from '@nestjs/common';
import { HttpExceptionFilter } from '@common/filters/http-exception.filter';
import { LoggingInterceptor } from '@common/interceptors/logging.interceptor';
import { CustomLoggerService } from './logger.service';

export const LOGGER_CONTEXT = Symbol('LOGGER_CONTEXT');

@Global()
@Module({
  providers: [
    {
      provide: LOGGER_CONTEXT,
      useValue: 'AppLogger',
    },
    CustomLoggerService,
    HttpExceptionFilter,
    LoggingInterceptor,
  ],
  exports: [CustomLoggerService, HttpExceptionFilter, LoggingInterceptor],
})
export class LoggingModule {
  static register(context: string): DynamicModule {
    return {
      module: LoggingModule,
      providers: [
        {
          provide: LOGGER_CONTEXT,
          useValue: context,
        },
        CustomLoggerService,
      ],
      exports: [CustomLoggerService],
    };
  }
}
