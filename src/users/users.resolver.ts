import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { Res, UnauthorizedException, UseGuards } from '@nestjs/common';
import { RefreshToken } from './entities/refresh-token.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LogoutResponse } from './entities/logout.entity';

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

  @Mutation(() => LogoutResponse)
  logout(@Context() context) {
    const token = context?.res?.req?.cookies?.refreshToken;
    console.log('Logout token:', token);

    return this.usersService.logout(token, context.res);
  }

  @Query(() => User)
  profile(@Context() context) {
    const token = context?.res?.req?.cookies?.refreshToken;

    return this.usersService.profile(token);
  }

  // @Query(() => User)
  // @UseGuards(JwtAuthGuard)
  // profile(@Context() context) {
  //   console.log('Profile context:', context);
  //   return context.req.user;
  // }
}
