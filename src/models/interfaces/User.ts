import {
  IsString,
  MinLength,
  MaxLength,
  IsStrongPassword,
  IsOptional,
} from 'class-validator';
import { UserRole } from '../../roles/roles.enum';

export interface User {
  userId: number;
  username: string;
  role: UserRole;
  phone: string;
  password: string;
}

export interface UserLoginDetails {
  username: string;
  password: string;
}

export interface UserDetails {
  id: number;
  username: string;
  phone?: string;
  role: UserRole;
}

export interface AuthenticatedUser {
  sub: number; //for the user id
  username: string;
  role: UserRole;
}

export class UserBaseDTO {
  @IsString()
  @MinLength(3, { message: 'Username must be at least 3 characters long' })
  @MaxLength(20, { message: 'Username must be at most 20 characters long' })
  username: string;

  phone: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(100, { message: 'Password must be at most 100 characters long' })
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 0,
    },
    {
      message:
        'Password must contain 1 uppercase letter, 1 lowercase letter, 1 number, and be at least 8 characters long',
    },
  )
  password: string;
}

export class UserUpdateDTO {
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'Username must be at least 3 characters long' })
  @MaxLength(20, { message: 'Username must be at most 20 characters long' })
  username?: string;

  @IsOptional()
  phone?: string;
}
