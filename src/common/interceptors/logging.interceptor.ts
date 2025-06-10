import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { CustomLoggerService, LogContext } from '@common/services/logger.service';
import { HttpArgumentsHost } from '@nestjs/common/interfaces';

//TODO:types to correct places
interface CustomRequest extends Request {
  id: string;
  user?: {
    id?: string;
    sub?: string;
    userId?: string;
  };
}

interface RequestLogData {
  requestId: string;
  method: string;
  url: string;
  path: string;
  query: Record<string, unknown>;
  headers: Record<string, unknown>;
  userAgent?: string;
  ip: string;
  userId?: string;
  correlationId?: string;
  body?: unknown;
  timestamp: string;
}

interface ResponseLogData {
  requestId: string;
  method: string;
  url: string;
  statusCode: number;
  contentLength?: string;
  duration: number;
  timestamp: string;
  userId?: string;
  correlationId?: string;
}

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly sensitiveFields = [
    'password',
    'token',
    'authorization',
    'auth',
    'secret',
    'key',
    'api-key',
    'x-api-key',
    'cookie',
    'session',
    'csrf',
    'ssn',
    'social-security',
    'credit-card',
    'cvv',
    'pin',
  ];

  private readonly sensitiveHeaders = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
    'x-access-token',
    'x-refresh-token',
    'authentication',
    'proxy-authorization',
  ];

  constructor(private readonly logger: CustomLoggerService) {
    this.logger.setContext('HTTP');
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext: HttpArgumentsHost = context.switchToHttp();

    const request = httpContext.getRequest<CustomRequest>();
    const response = httpContext.getResponse<Response>();

    if (!request.id) {
      request.id = uuidv4();
    }

    response.setHeader('X-Request-ID', request.id);

    const startTime = Date.now();
    this.logIncomingRequest(request);

    return next.handle().pipe(
      tap(responseData => {
        const duration = Date.now() - startTime;
        this.logOutgoingResponse(request, response, duration, responseData);
        this.logPerformanceMetric(request, duration, true);
      }),
      catchError(error => {
        const duration = Date.now() - startTime;

        this.logErrorResponse(
          request,
          duration,
          error as Error & { status?: number; statusCode?: number },
        );
        this.logPerformanceMetric(request, duration, false);
        throw error;
      }),
    );
  }

  private logIncomingRequest(request: CustomRequest): void {
    const requestData: RequestLogData = {
      requestId: request.id,
      method: request.method,
      url: request.url,
      path: request.path,
      query: this.sanitizeData(request.query) as Record<string, unknown>,
      headers: this.sanitizeHeaders(request.headers),
      userAgent: request.get('User-Agent'),
      ip: this.getClientIp(request),
      userId: this.extractUserId(request),
      correlationId: this.extractCorrelationId(request),
      body: this.shouldLogBody(request) ? this.sanitizeData(request.body) : undefined,
      timestamp: new Date().toISOString(),
    };

    this.logger.info('Incoming HTTP Request', {
      requestId: requestData.requestId,
      correlationId: requestData.correlationId,
      userId: requestData.userId,
      operation: `${requestData.method} ${requestData.path}`,
      metadata: {
        request: requestData,
        category: 'http_request',
      },
    });

    this.checkForSecurityConcerns(request, requestData);
  }

  private logOutgoingResponse(
    request: CustomRequest,
    response: Response,
    duration: number,
    responseData?: unknown,
  ): void {
    const responseLogData: ResponseLogData = {
      requestId: request.id,
      method: request.method,
      url: request.url,
      statusCode: response.statusCode,
      contentLength: response.get('Content-Length'),
      duration,
      timestamp: new Date().toISOString(),
      userId: this.extractUserId(request),
      correlationId: this.extractCorrelationId(request),
    };

    const logLevel = this.getLogLevelForStatus(response.statusCode);
    const message = `HTTP Response: ${request.method} ${request.path} - ${response.statusCode} (${duration}ms)`;

    const logContext: LogContext = {
      requestId: responseLogData.requestId,
      correlationId: responseLogData.correlationId,
      userId: responseLogData.userId,
      operation: `${request.method} ${request.path}`,
      duration,
      metadata: {
        response: responseLogData,
        responseSize: this.calculateResponseSize(responseData),
        category: 'http_response',
      },
    };

    if (logLevel === 'error') {
      this.logger.error(message, undefined, logContext);
    } else {
      this.logger[logLevel](message, logContext);
    }

    const slowThreshold = parseInt(process.env.SLOW_REQUEST_THRESHOLD || '5000', 10);
    if (duration > slowThreshold) {
      this.logger.warn(`Slow HTTP Response detected: ${duration}ms`, {
        requestId: responseLogData.requestId,
        correlationId: responseLogData.correlationId,
        userId: responseLogData.userId,
        operation: `${request.method} ${request.path}`,
        duration,
        metadata: {
          threshold: slowThreshold,
          category: 'performance_alert',
        },
      });
    }
  }

  private logErrorResponse(
    request: CustomRequest,
    duration: number,
    error: Error & { status?: number; statusCode?: number },
  ): void {
    this.logger.error(
      `HTTP Request Error: ${request.method} ${request.path} (${duration}ms)`,
      error.stack,
      {
        requestId: request.id,
        correlationId: this.extractCorrelationId(request),
        userId: this.extractUserId(request),
        operation: `${request.method} ${request.path}`,
        duration,
        metadata: {
          error: {
            name: error.name,
            message: error.message,
            status: error.status || error.statusCode,
          },
          category: 'http_error',
        },
      },
    );
  }

  private logPerformanceMetric(request: CustomRequest, duration: number, success: boolean): void {
    const operationName = this.getOperationName(request);
    this.logger.logPerformance(operationName, duration, success, {
      method: request.method,
      path: request.path,
      userId: this.extractUserId(request),
    });
  }

  private sanitizeData(data: unknown): unknown {
    if (!data || typeof data !== 'object') {
      return data;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.sanitizeData(item));
    }

    const sanitized: Record<string, unknown> = { ...(data as Record<string, unknown>) };

    for (const key in sanitized) {
      if (Object.prototype.hasOwnProperty.call(sanitized, key)) {
        const lowerKey = key.toLowerCase();
        if (this.sensitiveFields.some(field => lowerKey.includes(field))) {
          sanitized[key] = '[REDACTED]';
        } else if (sanitized[key] && typeof sanitized[key] === 'object') {
          sanitized[key] = this.sanitizeData(sanitized[key]);
        }
      }
    }
    return sanitized;
  }

  private sanitizeHeaders(headers: Request['headers']): Record<string, unknown> {
    const sanitized: Record<string, unknown> = { ...headers };

    this.sensitiveHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });

    Object.keys(sanitized).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (this.sensitiveFields.some(field => lowerKey.includes(field))) {
        sanitized[key] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  private shouldLogBody(request: Request): boolean {
    const contentType = request.get('Content-Type') || '';
    const contentLength = parseInt(request.get('Content-Length') || '0', 10);

    if (
      contentType.includes('multipart/form-data') ||
      contentType.includes('application/octet-stream') ||
      contentLength > 10000
    ) {
      return false;
    }

    const sensitivePaths = ['/auth/login', '/auth/register', '/password'];
    return !sensitivePaths.some(path => request.path.includes(path));
  }

  private getClientIp(request: Request): string {
    const xForwardedFor = request.headers['x-forwarded-for'];

    return (
      (typeof xForwardedFor === 'string' && xForwardedFor.split(',')[0]?.trim()) ||
      (request.headers['x-real-ip'] as string) ||
      request.socket.remoteAddress ||
      'unknown'
    );
  }

  private extractUserId(request: CustomRequest): string | undefined {
    const user = request.user;
    return user?.id || user?.sub || user?.userId || (request.headers['x-user-id'] as string);
  }

  private extractCorrelationId(request: Request): string | undefined {
    return (
      (request.headers['x-correlation-id'] as string) ||
      (request.headers['correlation-id'] as string) ||
      (request.headers['x-trace-id'] as string)
    );
  }

  private getLogLevelForStatus(statusCode: number): 'info' | 'warn' | 'error' {
    if (statusCode >= 500) return 'error';
    if (statusCode >= 400) return 'warn';
    return 'info';
  }

  private getOperationName(request: Request): string {
    const path = request.path
      .replace(/\/\d+/g, '/:id')
      .replace(/\/[a-f0-9-]{36}/g, '/:uuid')
      .replace(/[^a-zA-Z0-9_/]/g, '_');

    return `http_${request.method.toLowerCase()}${path.replace(/\//g, '_')}`;
  }

  private calculateResponseSize(responseData: unknown): number {
    if (!responseData) return 0;
    try {
      return JSON.stringify(responseData).length;
    } catch {
      return 0;
    }
  }

  private checkForSecurityConcerns(request: Request, requestData: RequestLogData): void {
    const concerns: string[] = [];
    const urlParams = request.url.toLowerCase();

    if (
      urlParams.includes('<script') ||
      urlParams.includes('javascript:') ||
      urlParams.includes('onerror=')
    ) {
      concerns.push('potential_xss');
    }
    if (urlParams.includes('union') && urlParams.includes('select')) {
      concerns.push('potential_sql_injection');
    }
    if (urlParams.includes('../') || urlParams.includes('..\\')) {
      concerns.push('potential_path_traversal');
    }

    const userAgent = request.get('User-Agent')?.toLowerCase() || '';
    if (
      userAgent.includes('bot') ||
      userAgent.includes('crawler') ||
      userAgent.includes('spider')
    ) {
      concerns.push('automated_client');
    }
    if (!request.get('User-Agent')) {
      concerns.push('missing_user_agent');
    }

    if (concerns.length > 0) {
      this.logger.logSecurityEvent('security_concern_detected', {
        concerns,
        requestId: requestData.requestId,
        method: request.method,
        url: request.url,
        ip: requestData.ip,
        userAgent: requestData.userAgent,
      });
    }
  }
}
