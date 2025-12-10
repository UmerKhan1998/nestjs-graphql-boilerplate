import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { Res, UseGuards } from '@nestjs/common';
import { RefreshToken } from './entities/refresh-token.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

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

  @Query(() => User)
  profile(@Context() context) {
    console.log(context);

    return {
      _id: '123',
      username: 'john',
      email: 'john@example.com',
    };
  }

  // @Query(() => User)
  // @UseGuards(JwtAuthGuard)
  // profile(@Context() context) {
  //   console.log('Profile context:', context);
  //   return context.req.user;
  // }
}
