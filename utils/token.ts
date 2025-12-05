import * as jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

interface TokenPayload {
  user: string | number;
}

interface GeneratedTokens {
  accessToken: string;
  refreshToken: string;
  jti: string;
}

export const generateTokens = (user: any): GeneratedTokens => {
  const jti = uuidv4(); // Unique token ID

  const accessToken = jwt.sign(
    { user } as TokenPayload,
    process.env.JWT_SECRET || 'fallback-secret',
    {
      expiresIn: '15m',
      jwtid: jti, // use the same jti
    },
  );

  const refreshToken = jwt.sign(
    { user } as TokenPayload,
    process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
    { expiresIn: '7d' },
  );

  return { accessToken, refreshToken, jti };
};
