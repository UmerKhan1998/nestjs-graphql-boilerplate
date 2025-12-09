import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateUserInput } from './dto/create-user.input';
import { UpdateUserInput } from './dto/update-user.input';
import { User as UserModel } from './schemas/user.schema';
import { validatePassword } from 'utils/password.validator';
import * as bcrypt from 'bcryptjs';
import { generateTokens } from 'utils/token';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(UserModel.name)
    private userModel: Model<UserModel>,
  ) {}

  async register(createUserInput: CreateUserInput, res) {
    const { username, email, password } = createUserInput;

    // 🔍 Validate password manually
    const passwordError = validatePassword(createUserInput.password);
    if (passwordError) {
      throw new BadRequestException(passwordError);
    }

    const existingUser = await this.userModel.findOne({
      email: createUserInput.email,
    });

    if (existingUser) {
      throw new ConflictException('User already exists with this email');
    }

    // 🔒 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      refreshToken: '',
    });

    const { accessToken, refreshToken } = generateTokens({
      id: newUser?._id?.toString(),
      username: newUser?.username,
      email: newUser?.email,
    });

    newUser['refreshToken'] = refreshToken;

    await newUser.save();

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // ✅ Return safe response (without password)
    return newUser;
  }

  async login(createUserInput: CreateUserInput, res) {
    const { email, password } = createUserInput;

    const newUser = await this.userModel.findOne({ email });
    if (!newUser) throw new UnauthorizedException('Invalid credentials');

    const isPasswordValid = await bcrypt.compare(password, newUser.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid credentials');

    const { accessToken, refreshToken } = generateTokens({
      id: newUser?._id?.toString(),
      username: newUser?.username,
      email: newUser?.email,
    });

    newUser['refreshToken'] = refreshToken;

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return newUser;
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
