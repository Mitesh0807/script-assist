import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Reflector } from '@nestjs/core';
import { LOG_PERFORMANCE } from './logging.decorator';
import { CustomLoggerService } from '@common/services/logger.service';

@Injectable()
export class PerformanceInterceptor implements NestInterceptor {
  constructor(
    private readonly logger: CustomLoggerService,
    private readonly reflector: Reflector,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const operation = this.reflector.get<string>(LOG_PERFORMANCE, context.getHandler());

    if (!operation) {
      return next.handle();
    }

    const startTime = Date.now();
    const endTimer = this.logger.startPerformanceTimer(operation);

    return next.handle().pipe(
      tap(() => {
        endTimer();
      }),
      catchError(error => {
        const duration = Date.now() - startTime;
        this.logger.logPerformance(operation, duration, false);
        throw error;
      }),
    );
  }
}
