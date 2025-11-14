import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SessionService } from './sessions.service';
import { UserSessions } from 'src/models/entities/userSessions.entity';

@Module({
  imports: [TypeOrmModule.forFeature([UserSessions])],
  providers: [SessionService],
  exports: [SessionService],
})
export class SessionsModule {}
