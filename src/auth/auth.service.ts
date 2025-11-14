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
import * as dotenv from 'dotenv';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from 'src/core/sessions/sessions.service';
import { SessionDetails } from 'src/models/interfaces/Session';
import type { Request } from 'express';

dotenv.config();

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
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '10m',
    });
    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '30d',
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

    try {
      await this.sessionService.createSession(sessionDetails);
    } catch (error) {
      console.log('Failed to create session');
      throw new InternalServerErrorException(
        `Failed to create session: ${error}`,
      );
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
      const payload: AuthenticatedUser =
        await this.jwtService.verifyAsync(refreshToken);
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

      const newAccessToken = await this.jwtService.signAsync(
        { sub: payload.sub, username: payload.username, role: payload.role },
        { expiresIn: '10m' },
      );

      // create new refresh token using the same remaining TTL as the existing session
      const newRefreshToken = await this.jwtService.signAsync(
        { sub: payload.sub, username: payload.username, role: payload.role },
        { expiresIn: remainingTtl },
      );

      // update the refresh token in the database
      session.refreshToken = newRefreshToken;
      await this.sessionService.updateSession(session);

      console.log('Generated new access token for user:', payload.username);
      return { access_token: newAccessToken, refresh_token: newRefreshToken };
    } catch (error) {
      console.log('Error refreshing token:', error);
      throw new InternalServerErrorException('Refresh token invalid/expired');
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
    console.log(`Logging out user ID ${userId}`);
    const session = await this.sessionService.findByRefreshToken(refreshToken);
    if (!session || session.userId !== userId) {
      throw new UnauthorizedException('Invalid token or user mismatch');
    }
    await this.sessionService.revokeSession(refreshToken);
    return { message: 'Logged out successfully' };
  }
}
