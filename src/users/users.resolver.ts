import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { Res } from '@nestjs/common';

@Resolver(() => User)
export class UsersResolver {
  constructor(private readonly usersService: UsersService) {}

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

  // @Query(() => [User], { name: 'users' })
  // findAll() {
  //   return this.usersService.findAll();
  // }

  @Query(() => User, { name: 'user' })
  findOne(@Args('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Mutation(() => User)
  updateUser(@Args('updateUserInput') updateUserInput: UpdateUserInput) {
    return this.usersService.update(updateUserInput.id, updateUserInput);
  }

  @Mutation(() => User)
  removeUser(@Args('id') id: string) {
    return this.usersService.remove(id);
  }
}
