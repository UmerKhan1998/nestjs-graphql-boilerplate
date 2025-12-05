// src/guards/gql-throttler.guard.ts
import { ExecutionContext, Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class GqlThrottlerGuard extends ThrottlerGuard {
  protected getRequest(context: ExecutionContext) {
    const ctxType = context.getType<'http' | 'graphql'>();

    if (ctxType === 'graphql') {
      const gqlCtx = GqlExecutionContext.create(context);
      const req = gqlCtx.getContext().req;
      if (!req) {
        throw new Error('GraphQL context does not contain req object!');
      }
      return req;
    }

    return context.switchToHttp().getRequest();
  }
}
