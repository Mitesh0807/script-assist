import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  BadRequestException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { QueryFailedError, EntityNotFoundError } from 'typeorm';
import { CustomLoggerService } from '@common/services/logger.service';

type ErrorDetails = Record<string, unknown> | ValidationErrorDetail[];

export interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: ErrorDetails;
    timestamp: string;
    path: string;
    requestId?: string;
    correlationId?: string;
  };
}

export interface ValidationErrorDetail {
  field: string;
  value: unknown;
  constraints: Record<string, string>;
}

interface RequestUser {
  id?: string;
  sub?: string;
  userId?: string;
}

interface CustomRequest extends Request {
  id?: string;
  user?: RequestUser;
}

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: CustomLoggerService) {
    this.logger.setContext(HttpExceptionFilter.name);
  }

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<CustomRequest>();

    const { status, errorResponse } = this.processException(exception, request);

    this.logError(exception, request, status, errorResponse);

    this.setSecurityHeaders(response);

    response.status(status).json(errorResponse);
  }

  private processException(
    exception: unknown,
    request: CustomRequest,
  ): { status: number; errorResponse: ErrorResponse } {
    const requestId = this.extractRequestId(request);
    const correlationId = this.extractCorrelationId(request);
    const timestamp = new Date().toISOString();
    const path = request.url;

    let status: number;
    let code: string;
    let message: string;
    let details: ErrorDetails | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'string') {
        code = this.getErrorCodeFromStatus(status);
        message = exceptionResponse;
      } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const responseObj = exceptionResponse as Record<string, unknown>;
        code = (responseObj.error as string) || this.getErrorCodeFromStatus(status);
        message = (responseObj.message as string) || exception.message;
        details = responseObj.details as ErrorDetails;

        if (
          exception instanceof BadRequestException &&
          responseObj.message &&
          Array.isArray(responseObj.message)
        ) {
          details = this.formatValidationErrors(responseObj.message);
          message = 'Validation failed';
        }
      } else {
        code = this.getErrorCodeFromStatus(status);
        message = exception.message;
      }
    } else if (exception instanceof QueryFailedError) {
      status = HttpStatus.BAD_REQUEST;
      code = 'DATABASE_ERROR';
      message = 'Database operation failed';
      details = this.formatDatabaseError(exception);
    } else if (exception instanceof EntityNotFoundError) {
      status = HttpStatus.NOT_FOUND;
      code = 'ENTITY_NOT_FOUND';
      message = 'Requested resource not found';
    } else if (exception instanceof Error) {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      code = 'INTERNAL_SERVER_ERROR';
      message =
        process.env.NODE_ENV === 'production' ? 'An unexpected error occurred' : exception.message;
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      code = 'UNKNOWN_ERROR';
      message = 'An unknown error occurred';
    }

    const errorResponse: ErrorResponse = {
      success: false,
      error: {
        code,
        message,
        ...(details && { details }),
        timestamp,
        path,
        ...(requestId && { requestId }),
        ...(correlationId && { correlationId }),
      },
    };

    return { status, errorResponse };
  }

  private logError(
    exception: unknown,
    request: CustomRequest,
    status: number,
    errorResponse: ErrorResponse,
  ): void {
    const logContext = {
      requestId: this.extractRequestId(request),
      correlationId: this.extractCorrelationId(request),
      userId: this.extractUserId(request),
      operation: `${request.method} ${request.url}`,
      metadata: {
        userAgent: request.get('User-Agent'),
        ip: request.ip || request.connection.remoteAddress,
        statusCode: status,
        errorCode: errorResponse.error.code,
      },
    };

    if (status >= 500) {
      this.logger.error(
        `Server Error: ${errorResponse.error.message}`,
        exception instanceof Error ? exception.stack : undefined,
        logContext,
      );

      if (status === HttpStatus.UNAUTHORIZED || status === HttpStatus.FORBIDDEN) {
        this.logger.logSecurityEvent(
          'authentication_failure',
          {
            path: request.url,
            method: request.method,
            ip: request.ip,
            userAgent: request.get('User-Agent'),
          },
          logContext,
        );
      }
    } else if (status >= 400) {
      this.logger.warn(`Client Error: ${errorResponse.error.message}`, logContext);

      if (this.isPotentialSecurityThreat(request, status)) {
        this.logger.logSecurityEvent(
          'potential_attack',
          {
            path: request.url,
            method: request.method,
            statusCode: status,
            ip: request.ip,
            userAgent: request.get('User-Agent'),
          },
          logContext,
        );
      }
    } else {
      this.logger.info(`Request Error: ${errorResponse.error.message}`, logContext);
    }
  }

  private formatValidationErrors(errors: Record<string, unknown>[]): ValidationErrorDetail[] {
    return errors.map(error => {
      if (typeof error === 'string') {
        return {
          field: 'unknown',
          value: null,
          constraints: { validation: error },
        };
      }

      return {
        field: (error.property as string) || 'unknown',
        value: error.value,
        constraints: (error.constraints as Record<string, string>) || {},
      };
    });
  }

  private formatDatabaseError(
    error: QueryFailedError & { code?: string; detail?: string; constraint?: string },
  ): Record<string, unknown> {
    if (process.env.NODE_ENV === 'production') {
      return {
        type: 'database_constraint_violation',
        message: 'The operation could not be completed due to data constraints',
      };
    }

    return {
      code: error.code,
      detail: error.detail,
      constraint: error.constraint,
    };
  }

  private getErrorCodeFromStatus(status: number): string {
    const statusCodeMap: Record<number, string> = {
      [HttpStatus.BAD_REQUEST]: 'BAD_REQUEST',
      [HttpStatus.UNAUTHORIZED]: 'UNAUTHORIZED',
      [HttpStatus.FORBIDDEN]: 'FORBIDDEN',
      [HttpStatus.NOT_FOUND]: 'NOT_FOUND',
      [HttpStatus.METHOD_NOT_ALLOWED]: 'METHOD_NOT_ALLOWED',
      [HttpStatus.CONFLICT]: 'CONFLICT',
      [HttpStatus.UNPROCESSABLE_ENTITY]: 'UNPROCESSABLE_ENTITY',
      [HttpStatus.TOO_MANY_REQUESTS]: 'TOO_MANY_REQUESTS',
      [HttpStatus.INTERNAL_SERVER_ERROR]: 'INTERNAL_SERVER_ERROR',
      [HttpStatus.BAD_GATEWAY]: 'BAD_GATEWAY',
      [HttpStatus.SERVICE_UNAVAILABLE]: 'SERVICE_UNAVAILABLE',
      [HttpStatus.GATEWAY_TIMEOUT]: 'GATEWAY_TIMEOUT',
    };

    return statusCodeMap[status] || 'UNKNOWN_ERROR';
  }

  private extractRequestId(request: CustomRequest): string | undefined {
    return (
      (request.headers['x-request-id'] as string) ||
      (request.headers['request-id'] as string) ||
      request.id
    );
  }

  private extractCorrelationId(request: Request): string | undefined {
    return (
      (request.headers['x-correlation-id'] as string) ||
      (request.headers['correlation-id'] as string)
    );
  }

  private extractUserId(request: CustomRequest): string | undefined {
    const user = request.user;
    return user?.id || user?.sub || user?.userId;
  }

  private isPotentialSecurityThreat(request: Request, status: number): boolean {
    const suspiciousPatterns = [
      /\.\./, // Path traversal
      /script/i, // XSS attempts
      /union.*select/i, // SQL injection
      /exec\(/, // Code injection
      /eval\(/, // Code injection
    ];

    const url = request.url.toLowerCase();
    const hasServerError = status >= 500;
    const hasSuspiciousPattern = suspiciousPatterns.some(pattern => pattern.test(url));
    const hasUnusualHeaders = this.hasUnusualHeaders(request);

    return hasServerError || hasSuspiciousPattern || hasUnusualHeaders;
  }

  private hasUnusualHeaders(request: Request): boolean {
    const suspiciousHeaders = ['x-forwarded-host', 'x-real-ip', 'x-forwarded-for'];

    return suspiciousHeaders.some(header => {
      const value = request.headers[header] as string;
      return value && (value.includes('<') || value.includes('>') || value.includes('script'));
    });
  }

  private setSecurityHeaders(response: Response): void {
    response.removeHeader('X-Powered-By');

    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');
  }
}
