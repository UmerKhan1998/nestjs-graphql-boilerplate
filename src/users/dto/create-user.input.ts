import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class CreateUserInput {
  @Field({ nullable: true })
  username?: string;

  @Field()
  password: string;

  @Field()
  email: string;

  @Field({ nullable: true })
  refreshToken?: string;
}
