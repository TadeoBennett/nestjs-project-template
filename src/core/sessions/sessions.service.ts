import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserSessions } from 'src/models/entities/userSessions.entity';
import { SessionDetails } from 'src/models/interfaces/Session';
import { Repository } from 'typeorm';
import { UnauthorizedException } from '@nestjs/common';

@Injectable()
export class SessionService {
  constructor(
    @InjectRepository(UserSessions)
    private sessionRepository: Repository<UserSessions>,
  ) {}

  async createSession(sessionDetails: SessionDetails): Promise<UserSessions> {
    const session = this.sessionRepository.create(sessionDetails);
    return this.sessionRepository.save(session);
  }

  async findByRefreshToken(
    refreshToken: string,
    validate: boolean = false,
  ): Promise<UserSessions | null> {
    const session = await this.sessionRepository.findOne({
      where: { refreshToken: refreshToken, revoked: false },
      relations: {
        user: true,
      },
    });

    if (validate && !session) {
      console.log('No session found for provided token.');
      throw new UnauthorizedException('Invalid refresh token');
    }

    //we want to validate and check expiry
    if (validate && session && session.expiresAt < new Date()) {
      console.log('Refresh token has expired.');
      throw new UnauthorizedException('Expired refresh token');
    }

    return session;
  }

  async updateSession(session: UserSessions): Promise<UserSessions> {
    return this.sessionRepository.save(session);
  }

  async revokeSession(token: string): Promise<void> {
    await this.sessionRepository.update(
      { refreshToken: token },
      { revoked: true },
    );
  }
}
