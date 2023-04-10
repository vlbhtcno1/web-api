import { IUser } from '../interfaces/user.interface';
import { ModelEntity } from '../../model.serializer';
import { LogCardEntity } from '../../../log_card/log_card.entity';
import { OneToMany } from 'typeorm';

export class UserEntity extends ModelEntity implements IUser {
  id: number;

  email: null | string;

  username: null | string;

  password: string;
}
