import {
  Column,
  Entity,
  Index,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Users } from './users.entity';

@Index('user_sessions_pkey', ['id'], { unique: true })
@Entity('user_sessions', { schema: 'public' })
export class UserSessions {
  @PrimaryGeneratedColumn({ type: 'integer', name: 'id' })
  id: number;

  @Column('character varying', { name: 'refresh_token', length: 512 })
  refreshToken: string;

  @Column('timestamp without time zone', { name: 'expires_at' })
  expiresAt: Date;

  @Column('timestamp without time zone', {
    name: 'created_at',
    nullable: true,
    default: () => 'now()',
  })
  createdAt: Date | null;

  @Column('character varying', {
    name: 'ip_address',
    nullable: true,
    length: 45,
  })
  ipAddress: string | null;

  @Column('text', { name: 'user_agent', nullable: true })
  userAgent: string | null;

  @Column('boolean', {
    name: 'revoked',
    nullable: true,
    default: () => 'false',
  })
  revoked: boolean | null;

  @ManyToOne(() => Users, (user) => user.userSessions, { eager: false })
  @JoinColumn({ name: 'user_id' })
  user: Users;

  @Column({ name: 'user_id', nullable: false })
  userId: number;
}
