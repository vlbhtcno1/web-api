import {
  Get,
  Put,
  Post,
  Body,
  Delete,
  Param,
  Controller,
  UseInterceptors,
  ClassSerializerInterceptor,
  HttpException,
  HttpStatus,
  UseGuards,
  Request, Response,
} from '@nestjs/common';
import { UserEntity } from './serializers/user.serializer';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/CreateUser.dto';
import { AuthenticationGuard } from '../../auth/guards/auth.guard';
import { AuthService } from '../../auth/auth.service';

@UseGuards(AuthenticationGuard)
@Controller('/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('/')
  async index() {
    return this.usersService.findAll();
  }

  @Get('/:id')
  async getById(@Param() params): Promise<UserEntity> {
    const user = await this.usersService.findById(params.id, ['messages']);
    this.throwUserNotFound(user);
    return user;
  }

  @Post('/')
  async create(@Body() inputs: CreateUserDto): Promise<UserEntity> {
    return await this.usersService.create(inputs);
  }

  @Put('/:id')
  async update(@Param() params, @Body() inputs: User): Promise<UserEntity> {
    const user = await this.usersService.findById(parseInt(params.id, 0));
    this.throwUserNotFound(user);
    return await this.usersService.update(user, inputs);
  }

  @Delete('/:id')
  async delete(@Param() params): Promise<boolean> {
    const user = await this.usersService.findById(parseInt(params.id, 0));
    this.throwUserNotFound(user);
    return await this.usersService.deleteById(params.id);
  }

  @Get('/users/:email')
  async geUsersByEmail(@Param() params) {
    return this.usersService.geUsersByEmail(params.email, null);
  }

  throwUserNotFound(user: User | UserEntity) {
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
  }
}

@UseGuards(AuthenticationGuard)
@Controller('/admin/user')
export class AdminUsersController {
  constructor(
    private readonly usersService: UsersService,
  ) {}

  @Post('/update')
  async update(@Request() request, @Response() response, @Param() params, @Body() inputs) {
    const user = await this.usersService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException('User don\'t exists', HttpStatus.NOT_FOUND);
    }
    if (user.is_admin) {
      const userNeedUpdate = await this.usersService.findById(inputs.id);
      this.throwUserNotFound(user);
      let dataUpdate = new User;
      if (inputs.email) dataUpdate.email = inputs.email;
      if (inputs.phone_number) dataUpdate.phone_number = inputs.phone_number;
      if (inputs.password) dataUpdate.password = await this.usersService.hashPassword(inputs.password);
      response.status(200).send(await this.usersService.update(userNeedUpdate, dataUpdate));
    } else {
      return response.status(403).send('FORBIDDEN');
    }
  }

  throwUserNotFound(user: User | UserEntity) {
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
  }
}
