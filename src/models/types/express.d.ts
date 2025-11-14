import { UserRole } from '../../roles/roles.enum';

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      sub: number;
      username: string;
      role: UserRole;
    };
  }
}
