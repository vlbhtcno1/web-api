import {
  Body,
  Controller,
  Delete,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Post,
  Put,
  Request, Response,
  UseGuards,
} from '@nestjs/common';
import { LogCardService } from './log_card.service';
import { AuthenticationGuard } from '../auth/guards/auth.guard';
import { UsersService } from '../models/users/users.service';

@Controller('/admin/log_card')
export class AdminLogCardController {
  constructor(
    private logCardService: LogCardService,
    private userService: UsersService,
  ) {
  }

  @UseGuards(AuthenticationGuard)
  @Get('list')
  async logCardList(@Request() request, @Response() response): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException('User don\'t exists', HttpStatus.NOT_FOUND);
    }
    if (user.is_admin) {
      let whereClause = {
        where: {user_id: request.query.userId},
        order: {
          id: "DESC" // "DESC"
        }
      };
      // @ts-ignore
      let logCards = await this.logCardService.getRepository().find(whereClause);
      let targetUser = await this.userService.findById(request.query.userId);
      let results = [];
      for (let item of logCards)
        results.push({
          id: item.id,
          card_type: item.card_type,
          card_name: item.card_name,
          card_code: item.card_code,
          card_seri: item.card_seri,
          create_at: item.create_at.getTime(),
          status: item.status,
          note: item.note,
          money: item.money,
          username: targetUser.username,
        })
      response.status(200).send(results);
    } else {
      return response.status(403).send('FORBIDDEN');
    }
  }

}
