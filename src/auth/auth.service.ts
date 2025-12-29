import {
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { generateTokens } from 'utils/token';
import { addToBlacklist, isBlacklisted } from 'utils/tokenBlacklist';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async register(createAuthDto: CreateAuthDto, res) {
    const { username, email, password } = createAuthDto;

    // 🔍 Check for existing user
    const existingUser = await this.userModel.findOne({
      $or: [{ username }, { email }],
    });
    if (existingUser) {
      throw new ConflictException('Username or email already exists');
    }

    // 🔒 Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 🧑‍💻 Create new user
    const newUser = new this.userModel({
      username,
      email,
      password: hashedPassword,
      refreshToken: '',
    });

    console.log('newUser', newUser);

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
    return {
      success: true,
      message: 'User registered successfully',
      accessToken,
    };
  }

  async login(createAuthDto: CreateAuthDto, res, req) {
    // const refreshToken = req.cookies?.refreshToken;
    // console.log('refreshToken', refreshToken);

    const { email, password } = createAuthDto;

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

    // 🧾 Generate JWT
    // const payload = user; // Simplified for this example
    // const token = await this.jwtService.signAsync(user);
    // console.log('User logged in successfully:', token);

    // send refresh token as secure cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return {
      success: true,
      message: 'Login successful',
      accessToken,
    };
  }

  async refresh(req, res) {
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

      if (decoded?.jti && isBlacklisted(decoded.jti)) {
        throw new HttpException(
          { success: false, message: 'Token has been blacklisted' },
          HttpStatus.UNAUTHORIZED,
        );
      }

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

      return { success: true, accessToken };
    } catch (error) {
      console.error('Refresh token error:', error);
      throw new HttpException(
        { success: false, message: 'Invalid or expired refresh token' },
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  async logout(req, res) {
    try {
      // ✅ Extract Bearer token from Authorization header
      const authHeader = req.headers['authorization'];
      const token = authHeader?.split(' ')[1];

      if (!token) {
        return res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ success: false, message: 'No token provided' });
      }

      // ✅ Verify token
      const decoded = jwt.verify(
        token,
        process.env.JWT_SECRET,
      ) as jwt.JwtPayload;

      // ✅ Add token jti to blacklist
      if (decoded?.jti) {
        addToBlacklist(decoded.jti);
      } else {
        throw new UnauthorizedException('Invalid token payload');
      }

      // ✅ Clear the refresh token cookie
      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      });

      // ✅ Send success message
      return res.status(HttpStatus.OK).json({
        success: true,
        message: 'Logout successful. Token has been blacklisted.',
      });
    } catch (error) {
      console.error('Logout error:', error.message);
      return res.status(HttpStatus.UNAUTHORIZED).json({
        success: false,
        message: 'Invalid or expired token',
      });
    }
  }
  // async logout(req, res) {
  //   try {
  //     const token = req.headers['authorization']?.split(' ')[1]; // Bearer <token>

  //     if (!token) {
  //       throw new UnauthorizedException('No token provided');
  //     }

  //     const decoded = jwt.verify(
  //       token,
  //       process.env.JWT_SECRET,
  //     ) as jwt.JwtPayload;

  //     if (!decoded?.jti) {
  //       throw new UnauthorizedException('Invalid token payload');
  //     }

  //     addToBlacklist(decoded.jti);

  //     // ❌ Clear refresh token cookie (if used)
  //     res.clearCookie('refreshToken', {
  //       httpOnly: true,
  //       secure: process.env.NODE_ENV === 'production',
  //       sameSite: 'strict',
  //     });

  //     return res.status(200).json({
  //       success: true,
  //       message: 'Logout successful. Token has been expired.',
  //     });
  //   } catch (error) {
  //     console.error('Refresh token error:', error);
  //     throw new HttpException(
  //       { success: false, message: 'Invalid or expired refresh token' },
  //       HttpStatus.UNAUTHORIZED,
  //     );
  //   }
  // }

  // // ✅ Logout: blacklist the refresh token
  // async logout(token: string) {
  //   try {
  //     const decoded = jwt.verify(
  //       token,
  //       process.env.JWT_REFRESH_SECRET,
  //     ) as jwt.JwtPayload;

  //     if (decoded.jti) {
  //       addToBlacklist(decoded.jti);
  //     } else {
  //       throw new UnauthorizedException('Invalid token payload');
  //     }

  //     return { message: 'Logout successful' };
  //   } catch (err) {
  //     throw new UnauthorizedException('Invalid or expired token');
  //   }
  // }
}
