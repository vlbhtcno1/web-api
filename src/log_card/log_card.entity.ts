import { Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { User } from '../models/users/entities/user.entity';

@Entity('log_card')
export class LogCardEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name:'card_type', length: 200 })
  card_type: string;

  @Column({ name:'card_name', length: 200 })
  card_name: string;

  @Column({ name:'card_code', length: 200 })
  card_code: string;

  @Column({ name:'card_seri', length: 200 })
  card_seri: string;

  @Column({ name:'create_at' })
  create_at: Date;

  @Column({ name:'status' })
  status: number;

  @Column({ name:'note', length: 200 })
  note: string;

  @Column({ name:'user_id' })
  user_id: number;

  @ManyToOne(
    () => User,
    user => user.logCards,
    { eager: true },
  )
  @JoinColumn({ name: 'user_id', referencedColumnName: 'id' })
  user: User;

  @Column({ name:'money' })
  money: number;
}
