// src/all-exceptions.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { GqlArgumentsHost, GqlContextType } from '@nestjs/graphql';
import { Response, Request } from 'express';
import { MyLoggerService } from './my-logger/my-logger.service';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new MyLoggerService(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const contextType = host.getType<GqlContextType>();

    let path = '';
    let method = '';
    let response: Response | null = null;

    if (contextType === 'http') {
      const httpCtx = host.switchToHttp();
      const req = httpCtx.getRequest<Request>();
      response = httpCtx.getResponse<Response>();

      path = req?.url ?? '';
      method = req?.method ?? '';
    }

    if (contextType === 'graphql') {
      const gqlHost = GqlArgumentsHost.create(host);
      const ctx = gqlHost.getContext();
      const info = gqlHost.getInfo();

      path = info?.fieldName ?? 'graphql';
      method = ctx?.req?.method ?? 'GRAPHQL';
      response = ctx?.res ?? null;
    }

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = 'Internal server error';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();
      message = typeof res === 'string' ? res : (res as any).message || res;
    } else if (exception instanceof Error) {
      message = exception.message;
    }

    const errorResponse = {
      success: false,
      statusCode: status,
      timestamp: new Date().toISOString(),
      path,
      method,
      message,
    };

    this.logger.error(
      `❌ [${method}] ${path} → ${JSON.stringify(message)}`,
      exception instanceof Error ? exception.stack : undefined,
    );

    if (contextType === 'http' && response && !response.headersSent) {
      return response.status(status).json(errorResponse);
    }

    throw exception; // Let Apollo handle GraphQL errors
  }
}
