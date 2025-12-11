import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class LogoutResponse {
  @Field()
  success: boolean;

  @Field()
  message: string;
}
