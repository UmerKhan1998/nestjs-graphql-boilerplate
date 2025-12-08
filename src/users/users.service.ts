import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { User } from './entities/user.entity';
import { User as UserModel } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(UserModel.name)
    private userModel: Model<UserModel>,
  ) {}

  async create(createUserInput: CreateUserInput): Promise<UserModel> {
    const existingUser = await this.userModel.findOne({
      email: createUserInput.email,
    });

    if (existingUser) {
      throw new BadRequestException('User already exists with this email');
    }

    const created = new this.userModel(createUserInput);
    return created.save();
  }

  async findAll(): Promise<UserModel[]> {
    return await this.userModel.find().exec();
  }

  async findOne(id: string): Promise<UserModel> {
    const user = await this.userModel.findById(id);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async update(
    id: string,
    updateUserInput: UpdateUserInput,
  ): Promise<UserModel> {
    const updated = await this.userModel.findByIdAndUpdate(
      id,
      updateUserInput,
      {
        new: true,
      },
    );

    if (!updated) throw new NotFoundException('User not found');
    return updated;
  }

  async remove(id: string): Promise<UserModel> {
    const deleted = await this.userModel.findByIdAndDelete(id);
    if (!deleted) throw new NotFoundException('User not found');
    return deleted;
  }
}
