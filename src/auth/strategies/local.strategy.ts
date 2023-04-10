import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserEntity } from '../../models/users/serializers/user.serializer';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'username' });
  }

  async validate(username: string, password: string): Promise<UserEntity> {
    const user = await this.authService.authentication(username, password);

    var censorWord = function (str) {
      return str[0] + "*".repeat(str.length - 3) + str.slice(-2);
    }
    
    var censorEmail = function (email){
      try {
        var arr = email.split("@");
        return censorWord(arr[0]) + "@" + censorWord(arr[1]);
      }catch(e) {
        console.log(e)
        return email;
      }
      
    }
    
    

    if (!user) {
      throw new UnauthorizedException();
    }

    try {
      user.email = censorEmail(user.email)
    }catch(e) {
      console.log(user.email)
      console.log(e)
    }

    return user;
  }
}
