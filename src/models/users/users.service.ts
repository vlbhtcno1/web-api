import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UsersRepository } from './users.repository';
import { UserEntity } from './serializers/user.serializer';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/CreateUser.dto';
import { Repository } from 'typeorm';
const crypto = require('crypto');

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UsersRepository) private usersRepository: UsersRepository,
  ) {}

  async findAll(
    relations: string[] = [],
    throwsException = false,
  ): Promise<UserEntity[]> {
    return await this.usersRepository.getAllEntity(relations, throwsException);
  }

  async create(inputs: CreateUserDto): Promise<UserEntity> {
    return await this.usersRepository.createEntity(inputs);
  }

  async findById(
    id: number,
    relations: string[] = [],
    throwsException = false,
  ): Promise<UserEntity> {
    return await this.usersRepository.getEntityById(
      id,
      relations,
      throwsException,
    );
  }

  async update(user: UserEntity, inputs: User): Promise<UserEntity> {
    return await this.usersRepository.updateEntity(user, inputs);
  }

  async deleteById(id: number): Promise<boolean> {
    return await this.usersRepository.deleteEntityById(id);
  }

  async geUsersByEmail(email: string, username: string): Promise<UserEntity[]> {
    return await this.usersRepository.getUsersByEmail(email, username);
  }

  async getUserByUserName(username: string): Promise<UserEntity> {
    return await this.usersRepository.getUserByUserName(username);
  }
  
  async getUserByEmail(username: string): Promise<UserEntity> {
    return await this.usersRepository.getUserByEmail(username);
  }
  async getUserByPhone(username: string): Promise<UserEntity> {
    return await this.usersRepository.getUserByPhone(username);
  }

  getRepository(): Repository<UserEntity> {
    return this.usersRepository;
  }

  async hashPassword(password: string): Promise<string> {
    return crypto.createHash('md5').update(password).digest("hex");
  }

}
