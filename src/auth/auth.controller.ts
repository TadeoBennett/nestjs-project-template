import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  Req,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import type { UserDetails, UserLoginDetails } from 'src/models/interfaces/User';
import { UserBaseDTO } from 'src/models/interfaces/User';
import { Public } from 'src/auth/auth.set_metadata';
import type { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('login')
  async signIn(
    @Body() user: UserLoginDetails,
    @Req() req: Request,
  ): Promise<{
    access_token: string;
    refresh_token: string;
    user: UserDetails;
  }> {
    console.log('Login attempt for user:', user.username);
    return await this.authService.signIn(user.username, user.password, req);
  }

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string) {
    if (!refreshToken) {
      console.log('No refresh token provided');
      throw new BadRequestException('Refresh token is required');
    }
    return await this.authService.refresh(refreshToken);
  }

  @HttpCode(HttpStatus.OK)
  @Public()
  @Post('signup')
  async signUp(@Body() user: UserBaseDTO): Promise<UserDetails> {
    return await this.authService.signUp(user);
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(
    @Body('refreshToken') refreshToken: string,
    @Req() req: Request,
  ) {
    console.log('Logout attempt for user ID:', req.user?.sub);
    if (!refreshToken) {
      console.log('No refresh token provided for logout');
      throw new BadRequestException('Refresh token is required for logout');
    }
    return this.authService.logout(req.user!.sub, refreshToken);
  }
}
