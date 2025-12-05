import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class User {
  @Field(() => ID)
  _id: string;

  @Field()
  username: string;

  @Field()
  password: string;

  @Field()
  email: string;

  @Field()
  refreshToken: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}
