import { Injectable, LoggerService, Scope } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import * as DailyRotateFile from 'winston-daily-rotate-file';
import { IncomingHttpHeaders } from 'http';

//TODO:types to correct places
export enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  DEBUG = 'debug',
  VERBOSE = 'verbose',
}

export interface LogContext {
  userId?: string;
  requestId?: string;
  correlationId?: string;
  operation?: string;
  duration?: number;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface PerformanceMetric {
  operation: string;
  duration: number;
  success: boolean;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

interface MinimalHttpRequest {
  method: string;
  url: string;
  get: (name: string) => string | undefined;
  ip?: string;
  connection?: {
    remoteAddress?: string;
  };
  headers: IncomingHttpHeaders;
}

interface MinimalHttpResponse {
  statusCode: number;
  get: (name: string) => string | undefined;
}

@Injectable({ scope: Scope.TRANSIENT })
export class CustomLoggerService implements LoggerService {
  private logger: winston.Logger;
  private context?: string;
  private performanceMetrics: PerformanceMetric[] = [];
  private readonly maxMetricsBuffer = 1000;

  constructor(private readonly configService: ConfigService) {
    this.initializeLogger();
  }

  private initializeLogger(): void {
    const logLevel = this.configService.get('LOG_LEVEL', 'info');
    const nodeEnv = this.configService.get('NODE_ENV', 'development');
    const appName = this.configService.get('APP_NAME', 'nestjs-app');
    const instanceId = this.configService.get('INSTANCE_ID', process.env.HOSTNAME || 'unknown');

    const logFormat = winston.format.combine(
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
      winston.format.errors({ stack: true }),
      winston.format.json(),
      winston.format.printf(({ timestamp, level, message, context, stack, ...meta }) => {
        const logEntry = {
          timestamp,
          level: level.toUpperCase(),
          service: appName,
          instance: instanceId,
          context: context || this.context,
          message,
          ...(stack ? { stack } : {}),
          ...meta,
        };
        return JSON.stringify(logEntry);
      }),
    );

    const consoleFormat = winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'HH:mm:ss' }),
      winston.format.printf(({ timestamp, level, message, context, ...meta }) => {
        const ctx = context || this.context;
        const metaStr = Object.keys(meta).length > 0 ? ` ${JSON.stringify(meta)}` : '';
        return `${timestamp} [${level}] [${ctx}] ${message}${metaStr}`;
      }),
    );

    const transports: winston.transport[] = [];

    if (nodeEnv === 'development') {
      transports.push(
        new winston.transports.Console({
          format: consoleFormat,
          level: logLevel,
        }),
      );
    } else {
      transports.push(
        new winston.transports.Console({
          format: logFormat,
          level: logLevel,
        }),
        new DailyRotateFile({
          filename: 'logs/app-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          zippedArchive: true,
          maxSize: '20m',
          maxFiles: '14d',
          format: logFormat,
          level: 'info',
        }),
        new DailyRotateFile({
          filename: 'logs/error-%DATE%.log',
          datePattern: 'YYYY-MM-DD',
          zippedArchive: true,
          maxSize: '20m',
          maxFiles: '30d',
          format: logFormat,
          level: 'error',
        }),
      );
    }

    this.logger = winston.createLogger({
      level: logLevel,
      transports,
      exceptionHandlers: [new winston.transports.File({ filename: 'logs/exceptions.log' })],
      rejectionHandlers: [new winston.transports.File({ filename: 'logs/rejections.log' })],
    });
  }

  setContext(context: string): void {
    this.context = context;
  }

  log(message: unknown, context?: LogContext): void {
    this.info(message, context);
  }

  info(message: unknown, context?: LogContext): void {
    this.writeLog(LogLevel.INFO, message, context);
  }

  error(message: unknown, trace?: string, context?: LogContext): void {
    this.writeLog(LogLevel.ERROR, message, { ...context, stack: trace });
  }

  warn(message: unknown, context?: LogContext): void {
    this.writeLog(LogLevel.WARN, message, context);
  }

  debug(message: unknown, context?: LogContext): void {
    this.writeLog(LogLevel.DEBUG, message, context);
  }

  verbose(message: unknown, context?: LogContext): void {
    this.writeLog(LogLevel.VERBOSE, message, context);
  }

  startPerformanceTimer(operation: string): () => void {
    const startTime = Date.now();
    return () => this.endPerformanceTimer(operation, startTime);
  }

  private endPerformanceTimer(operation: string, startTime: number, success = true): void {
    const duration = Date.now() - startTime;
    this.logPerformance(operation, duration, success);
  }

  logPerformance(
    operation: string,
    duration: number,
    success = true,
    metadata?: Record<string, unknown>,
  ): void {
    const metric: PerformanceMetric = {
      operation,
      duration,
      success,
      timestamp: new Date(),
      metadata,
    };

    this.performanceMetrics.push(metric);

    if (this.performanceMetrics.length > this.maxMetricsBuffer) {
      this.performanceMetrics = this.performanceMetrics.slice(-this.maxMetricsBuffer);
    }

    this.info(`Performance: ${operation}`, {
      operation,
      duration,
      success,
      metadata,
    });

    if (duration > 5000) {
      this.warn(`Slow operation detected: ${operation} took ${duration}ms`, {
        operation,
        duration,
        success,
        metadata,
      });
    }
  }

  logHttpRequest(req: MinimalHttpRequest, context?: LogContext): void {
    this.info('HTTP Request', {
      ...context,
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection?.remoteAddress,
      headers: this.sanitizeHeaders(req.headers),
    });
  }

  logHttpResponse(
    req: MinimalHttpRequest,
    res: MinimalHttpResponse,
    duration: number,
    context?: LogContext,
  ): void {
    this.info('HTTP Response', {
      ...context,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration,
      contentLength: res.get('Content-Length'),
    });
  }

  logSecurityEvent(event: string, details: Record<string, unknown>, context?: LogContext): void {
    this.warn(`Security Event: ${event}`, {
      ...context,
      event,
      details,
      severity: 'security',
    });
  }

  logBusinessEvent(event: string, details: Record<string, unknown>, context?: LogContext): void {
    this.info(`Business Event: ${event}`, {
      ...context,
      event,
      details,
      category: 'business',
    });
  }

  logDatabaseOperation(
    operation: string,
    duration: number,
    success: boolean,
    context?: LogContext,
  ): void {
    this.logPerformance(`db_${operation}`, duration, success, {
      ...context,
      category: 'database',
    });
  }

  logExternalServiceCall(
    service: string,
    operation: string,
    duration: number,
    success: boolean,
    context?: LogContext,
  ): void {
    this.logPerformance(`external_${service}_${operation}`, duration, success, {
      ...context,
      service,
      category: 'external',
    });
  }

  getPerformanceMetrics(operation?: string): PerformanceMetric[] {
    if (operation) {
      return this.performanceMetrics.filter(m => m.operation === operation);
    }
    return [...this.performanceMetrics];
  }

  clearPerformanceMetrics(): void {
    this.performanceMetrics = [];
  }

  private writeLog(
    level: LogLevel,
    message: unknown,
    context?: LogContext & { stack?: string },
  ): void {
    const safeContext = typeof context === 'string' ? { context } : context;

    const logEntry = {
      message: typeof message === 'string' ? message : JSON.stringify(message),
      context: this.context,
      ...safeContext,
    };

    this.logger[level](logEntry);
  }

  private sanitizeHeaders(headers: IncomingHttpHeaders): Record<string, string | undefined> {
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
    const sanitized: Record<string, string | undefined> = {};

    for (const key in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, key)) {
        if (sensitiveHeaders.includes(key.toLowerCase())) {
          sanitized[key] = '[REDACTED]';
        } else {
          const value = headers[key];
          sanitized[key] = Array.isArray(value) ? value.join(', ') : value;
        }
      }
    }

    return sanitized;
  }
}
