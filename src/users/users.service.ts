import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
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
import * as jwt from 'jsonwebtoken';
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

  async refreshToken(refreshToken: string, req) {
    try {
      const refreshToken = req.cookies?.refreshToken;

      if (!refreshToken) {
        throw new HttpException(
          {
            success: false,
            message: 'No refresh token or invalid refresh token provided',
          },
          HttpStatus.UNAUTHORIZED,
        );
      }

      const decoded: any = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
      );

      const user = await this.userModel.findById(decoded.user?.id);

      // Rotate tokens
      const { accessToken, refreshToken: newRefreshToken } = generateTokens({
        id: user?._id?.toString(),
        username: user?.username,
        email: user?.email,
      });

      await this.userModel.findByIdAndUpdate(user?._id, {
        refreshToken: newRefreshToken,
      });

      // ✅ Use cookie-parser globally, Nest will handle response
      req.res?.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Implement your refresh token logic here
      return {
        _id: 'dummyId',
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      console.error('Refresh token error:', error);
      throw new HttpException(
        { success: false, message: 'Invalid or expired refresh token' },
        HttpStatus.UNAUTHORIZED,
      );
    }
  }
}
