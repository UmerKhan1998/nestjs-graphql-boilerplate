import {
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  ExceptionFilter,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { MyLoggerService } from './my-logger/my-logger.service';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new MyLoggerService(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = 'Internal server error';

    // ✅ Handle known NestJS HTTP exceptions
    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();

      // Sometimes `getResponse()` returns a string, sometimes an object
      message = typeof res === 'string' ? res : (res as any).message || res;
    } else if (exception instanceof Error) {
      // ✅ Capture unexpected JS errors (runtime, DB, etc.)
      message = exception.message;
    }

    // ✅ Structured response object
    const errorResponse = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      method: request.method,
      message,
    };

    // ✅ Log with stack trace for internal debugging
    this.logger.error(
      `❌ [${request.method}] ${request.url} → ${JSON.stringify(message)}`,
      exception instanceof Error ? exception.stack : undefined,
    );

    // ✅ Send only once (no super.catch() to avoid double response)
    if (!response.headersSent) {
      response.status(status).json(errorResponse);
    }
  }
}
