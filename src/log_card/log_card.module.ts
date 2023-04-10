import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseModule } from 'src/databases/database.module';
import { LogCardEntity } from './log_card.entity';
import { AdminLogCardController } from './log_card.controller';
import { logCardProvider } from './log_card.provider';
import { LogCardService } from './log_card.service';
import { UserEntity } from '../models/users/serializers/user.serializer';
import { UsersService } from '../models/users/users.service';
import { UsersModule } from '../models/users/users.module';
import { UsersRepository } from '../models/users/users.repository';

@Module({
  imports: [
    UsersModule,
    TypeOrmModule.forFeature([UsersRepository]),
    DatabaseModule,
  ],
  controllers: [AdminLogCardController],
  providers: [...logCardProvider, LogCardService, UsersService],
})
export class LogCardModule { }
