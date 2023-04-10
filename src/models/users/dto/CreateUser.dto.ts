import { IsNotEmpty, IsString, MaxLength, IsEmail, MinLength } from 'class-validator';

export class CreateUserDto {
  // @IsString()
  // @MaxLength(255)
  // @IsNotEmpty()
  // name: string;

  // @IsEmail()
  // email: string;

  // @IsNotEmpty()
  // password: string;

  id: number;

  @IsNotEmpty({
    message: 'Tài khoản không được để trống!',
  })
  @MinLength(4, {
    message: 'Tài khoản phải từ 4 - 40 kí tự!',
  })
  @MaxLength(40, {
    message: 'Tài khoản phải từ 4 - 40 kí tự!',
  })
  username: string;

  @IsNotEmpty({
    message: 'Mật khẩu không được để trống!',
  })
  password: string;

  money: number;

  vip_level: number;

  vip_exp: number;

  phone_number: string;

  @IsNotEmpty({
    message: 'Email không được để trống!',
  })
  email: string;

  create_at: Date;

  is_exist: boolean;

  is_admin: boolean;
}
