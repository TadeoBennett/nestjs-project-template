import {
  Controller,
  Get,
  Delete,
  Patch,
  HttpCode,
  HttpStatus,
  UseGuards,
  Param,
  Body,
  Req,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from './users.service';
import { UserDetails, UserUpdateDTO } from 'src/models/interfaces/User';
import { AuthGuard } from 'src/auth/auth.guard';
import { Roles } from 'src/roles/roles.decorator';
import { UserRole } from 'src/roles/roles.enum';
import { Public } from 'src/auth/auth.set_metadata';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard) //require jwt token in header
  @Roles(UserRole.ADMIN) //require the admin role
  @Get()
  async findAll(): Promise<UserDetails[]> {
    console.log('UsersController: findAll called');
    return await this.usersService.findAll();
  }

  // Get user by id
  @HttpCode(HttpStatus.OK)
  @Public()
  @Get(':id')
  async findOne(@Param('id') id: number): Promise<UserDetails | null> {
    return await this.usersService.findOneUser(id);
  }

  //Delete a user by ID
  @HttpCode(HttpStatus.OK) // optional: you may use the NO_CONTENT status; note the client does not receive any data, just the response status, if used
  @UseGuards(AuthGuard)
  @Roles(UserRole.ADMIN)
  @Delete(':id')
  async remove(@Param('id') id: number): Promise<UserDetails | null> {
    return await this.usersService.removeUserById(id);
  }

  @Patch(':id')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @Roles(UserRole.ADMIN, UserRole.USER) //allow both admin and user roles
  async updateUser(
    @Param('id') id: number,
    @Body() updateUserDto: UserUpdateDTO,
    @Req() req: Request, //attached via the AuthGuard
  ) {
    const requester = req.user!;

    if (!requester || !requester.sub) {
      throw new NotFoundException('No user found in request.');
    }

    if (requester.role === UserRole.USER && requester.sub !== Number(id)) {
      throw new ForbiddenException('You can only update your own account');
    }

    // check if the user to be updated exists
    const userToUpdate = await this.usersService.findOneUserById(id);
    if (!userToUpdate) {
      throw new NotFoundException('User to update not found');
    }

    // check if the username already exists for another user
    if (
      updateUserDto.username &&
      updateUserDto.username !== userToUpdate.username
    ) {
      const existingUser = await this.usersService.findOneUserByUsername(
        updateUserDto.username,
      );
      if (existingUser) {
        throw new ForbiddenException('Username already taken');
      }
    }

    return await this.usersService.updateUserById(id, updateUserDto);
  }
}
