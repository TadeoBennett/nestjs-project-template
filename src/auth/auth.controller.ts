import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  Req,
  Res,
  BadRequestException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import type { UserDetails, UserLoginDetails } from 'src/models/interfaces/User';
import { UserBaseDTO } from 'src/models/interfaces/User';
import { Public } from 'src/auth/auth.set_metadata';
import { AuthGuard } from './auth.guard';
import { SessionService } from 'src/core/sessions/sessions.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private sessionService: SessionService,
  ) {}
  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Body() user: UserLoginDetails,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request,
  ) {
    const {
      access_token,
      refresh_token,
      user: userDetails,
    } = await this.authService.signIn(user.username, user.password, req);

    res.cookie('accessToken', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', //! Enable ONLY in production HTTPS
      sameSite: 'strict',
      maxAge: 10 * 60 * 1000,
    });

    res.cookie('refreshToken', refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', //! Enable ONLY in production HTTPS
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      path: '/',
    });

    return { user: userDetails }; // tokens NOT returned
  }

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const refreshToken = req.cookies['refreshToken'];
    if (!refreshToken) {
      throw new BadRequestException('Refresh token is missing');
    }

    const { access_token, refresh_token } =
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      await this.authService.refresh(refreshToken);

    res.cookie('accessToken', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
    });

    res.cookie('refreshToken', refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return { message: 'Tokens refreshed successfully' };
  }

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('signup')
  async signUp(@Body() user: UserBaseDTO): Promise<UserDetails> {
    return await this.authService.signUp(user);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const refreshToken = req.cookies['refreshToken'];
    const userId = req.user!.sub;

    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    await this.authService.logout(userId, refreshToken);

    res.clearCookie('accessToken', { path: '/' });
    res.clearCookie('refreshToken', { path: '/' });

    return { message: 'Logged out successfully' };
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @Post('logoutAll')
  async logoutAll(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const userId = req.user!.sub;

    const count = await this.sessionService.revokeAllUserSessions(userId);

    res.clearCookie('accessToken', { path: '/' });
    res.clearCookie('refreshToken', { path: '/' });

    return { message: `Revoked ${count} sessions successfully` };
  }
}
