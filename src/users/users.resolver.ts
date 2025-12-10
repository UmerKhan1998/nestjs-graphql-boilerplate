import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { Res } from '@nestjs/common';
import { RefreshToken } from './entities/refresh-token.entity';

@Resolver()
export class UsersResolver {
  constructor(private readonly usersService: UsersService) {}

  @Query(() => String)
  hello() {
    return 'Hello GraphQL';
  }

  @Mutation(() => User)
  register(
    @Args('createUserInput') createUserInput: CreateUserInput,
    // @Res({ passthrough: true }) res: Response,
    @Context() context,
  ) {
    return this.usersService.register(createUserInput, context.res);
  }

  @Mutation(() => User)
  login(
    @Args('createUserInput') createUserInput: CreateUserInput,
    // @Res({ passthrough: true }) res: Response,
    @Context() context,
  ) {
    return this.usersService.login(createUserInput, context.res);
  }

  @Mutation(() => RefreshToken)
  refreshToken(
    @Args('refreshToken', { type: () => String }) refreshToken: string,
    @Context() context,
  ) {
    return this.usersService.refreshToken(refreshToken, context?.req);
  }
}
