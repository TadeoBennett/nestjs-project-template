import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../core/users/users.service';
import {
  AuthenticatedUser,
  UserBaseDTO,
  UserDetails,
  UserLoginDetails,
} from '../models/interfaces/User';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from 'src/core/sessions/sessions.service';
import { SessionDetails } from 'src/models/interfaces/Session';
import type { Request } from 'express';
import { jwtConstants } from './jwt.constants';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private sessionService: SessionService,
  ) {}

  async signIn(
    username: string,
    incomingPassword: string,
    req: Request,
  ): Promise<{
    access_token: string;
    refresh_token: string;
    user: UserDetails;
  }> {
    const user = await this.usersService.findOneUserByUsername(username);
    if (!user) {
      throw new NotFoundException('A user with that username was not found.');
    }
    console.log('User retrieved for signIn:', user);
    const match = await bcrypt.compare(incomingPassword, user.password);
    if (!match) {
      throw new UnauthorizedException(
        'Username or password is incorrect. Try again or reset your password.',
      );
    }
    console.log('User found:', user);
    //generating the access token
    const payload = {
      sub: user.id,
      username: user.username,
      role: user.role,
    };
    console.log('Generating tokens with payload:', payload);
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: jwtConstants.accessTtl,
      secret: jwtConstants.secret,
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: jwtConstants.refreshTtl,
      secret: jwtConstants.secret,
    });

    const sessionDetails: SessionDetails = {
      userId: user.id,
      refreshToken: refreshToken,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
      createdAt: new Date(Date.now()),
      ipAddress: req.ip || '',
      userAgent: req.headers['user-agent'] || '',
      revoked: false,
    };

    console.log('Creating session with details:', sessionDetails);

    try {
      await this.sessionService.createSession(sessionDetails);
    } catch (error) {
      console.log('Failed to create session');
      if (error instanceof Error) {
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Refresh token expired');
        }
        if (error.name === 'JsonWebTokenError') {
          throw new UnauthorizedException('Invalid refresh token');
        }
      }
      throw new InternalServerErrorException('Token verification failed');
    }

    const userDetails: UserDetails = {
      id: user.id,
      username: user.username,
      role: user.role,
      phone: user.phone,
    };

    // Return token + minimal user info
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: userDetails,
    };
  }

  async refresh(refreshToken: string) {
    try {
      const payload: AuthenticatedUser = await this.jwtService.verifyAsync(
        refreshToken,
        {
          secret: jwtConstants.secret,
        },
      );
      const session = await this.sessionService.findByRefreshToken(
        refreshToken,
        true,
      );

      //check if the session is valid
      if (!session || session.expiresAt < new Date() || session.revoked) {
        console.log('Session invalid, expired, or revoked');
        throw new UnauthorizedException('Invalid session');
      }

      // Compute how many seconds remain until expiry
      const now = Math.floor(Date.now() / 1000);
      const expTime = Math.floor(session.expiresAt.getTime() / 1000);
      const remainingTtl = expTime - now;

      const [newAccessToken, newRefreshToken] = await Promise.all([
        this.jwtService.signAsync(
          { sub: payload.sub, username: payload.username, role: payload.role },
          { expiresIn: '10m', secret: jwtConstants.secret },
        ),
        this.jwtService.signAsync(
          { sub: payload.sub, username: payload.username, role: payload.role },
          { expiresIn: remainingTtl, secret: jwtConstants.secret },
        ),
      ]);

      // update the refresh token in the database
      session.refreshToken = newRefreshToken;
      await this.sessionService.updateSession(session);

      console.log('Generated new access token for user:', payload.username);
      return { access_token: newAccessToken, refresh_token: newRefreshToken };
    } catch (error) {
      console.log('Error refreshing token:', error);
      if (error instanceof Error) {
        if (error.name === 'TokenExpiredError') {
          throw new UnauthorizedException('Refresh token expired');
        }
        if (error.name === 'JsonWebTokenError') {
          throw new UnauthorizedException('Invalid refresh token');
        }
      }

      throw new InternalServerErrorException('Token verification failed');
    }
  }

  async signUp(user: UserBaseDTO): Promise<UserDetails> {
    const hash = await bcrypt.hash(
      user.password,
      parseInt(process.env.SALT_OR_ROUNDS ?? '10', 10),
    );
    const moddedUser: UserLoginDetails = { ...user, password: hash };
    const newUser = await this.usersService.create(moddedUser);
    return {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      phone: newUser.phone,
    };
  }

  async logout(userId: number, refreshToken: string) {
    const session = await this.sessionService.findByRefreshToken(refreshToken);
    console.log('Session found for logout:', session);
    if (!session || session.user.id !== userId) {
      throw new UnauthorizedException('Invalid token or user mismatch');
    }
    await this.sessionService.revokeSession(refreshToken);
    return { message: 'Logged out successfully' };
  }
}
