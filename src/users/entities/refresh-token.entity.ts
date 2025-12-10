import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class RefreshToken {
  @Field(() => ID)
  _id: string;

  @Field()
  refreshToken?: string;
}
