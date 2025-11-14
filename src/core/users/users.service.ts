import {
  ConflictException,
  NotFoundException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Users } from 'src/models/entities/users.entity';
import { UserRole } from 'src/roles/roles.enum';
import { UserDetails, UserUpdateDTO } from 'src/models/interfaces/User';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(Users)
    private userRepository: Repository<Users>,
  ) {}

  async findOneUserByUsername(
    username: string,
    validate: boolean = false,
  ): Promise<Users | null> {
    const user = await this.userRepository.findOne({ where: { username } });
    if (validate && !user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findOneUserById(
    id: number,
    validate: boolean = false,
  ): Promise<Users | null> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (validate && !user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findOneUser(id: number): Promise<UserDetails | null> {
    const user = await this.findOneUserById(id, true);
    return {
      id: user!.id,
      username: user!.username,
      role: user!.role,
      phone: user!.phone,
    };
  }

  async removeUserById(id: number): Promise<UserDetails> {
    const user = await this.findOneUserById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    await this.userRepository.remove(user);
    return {
      id: user.id,
      username: user.username,
      role: user.role,
      phone: user.phone,
    };
  }

  async updateUserById(
    id: number,
    updateUserDto: UserUpdateDTO,
  ): Promise<UserDetails> {
    const user = await this.findOneUserById(id, true);

    // merge fields (non null assertion since we validated user existence by passing true in findOneuserById)
    for (const key of Object.keys(updateUserDto) as (keyof UserUpdateDTO)[]) {
      const value = updateUserDto[key];
      if (value !== undefined) {
        user![key] = value;
      }
    }

    const updatedUser = await this.userRepository.save(user!);
    console.log('Updated user:', updatedUser);
    return {
      id: updatedUser.id,
      username: updatedUser.username,
      role: updatedUser.role,
      phone: updatedUser.phone,
    };
  }

  async create(user: { username: string; password: string }): Promise<Users> {
    const existingUser = await this.findOneUserByUsername(user.username);
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // create user entity
    const newUser = this.userRepository.create({
      username: user.username,
      password: user.password,
      role: UserRole.USER, // default role
    });

    return this.userRepository.save(newUser);
  }

  async findAll(): Promise<UserDetails[]> {
    return this.userRepository.find({
      select: ['id', 'username', 'role'], // don’t return password
    });
  }
}
