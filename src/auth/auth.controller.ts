import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Post,
  Request,
  Response,
  UseGuards,
  Header,
  Res,
  BadRequestException,
  Session,
  Param,
} from '@nestjs/common';
import { CreateUserDto } from '../models/users/dto/CreateUser.dto';
import { UsersService } from '../models/users/users.service';
import { AuthService } from './auth.service';
import { AuthenticationGuard } from './guards/auth.guard';
import { LocalAuthGuard } from './guards/local.guard';
import { UserEntity } from '../models/users/serializers/user.serializer';
import { REQUEST_URL, KEY_REQUEST, LINK_FLASH, LINK_CONFIG, LAUNCHER_VERSION } from '../config/constants';
import { v4 as uuid } from 'uuid';
import { SkipThrottle } from '@nestjs/throttler';
import { ServerListService } from '../server_list/server_list.service';
import { LogCardService } from '../log_card/log_card.service';
import { createConnection, Like } from 'typeorm';
import { connect } from 'http2';
import { LogCardEntity } from 'src/log_card/log_card.entity';
var _ = require('lodash');
const axios = require('axios').default;
var soap = require('soap');
var FormData = require('form-data');

const SERVER_CLOSED = 0;
const SERVER_OPEN = 2;
const SERVER_MAINTAIN = 1;
const SERVER_HOT = 3;

const VIETTEL = "VTT";
const MOBIFONE = "VMS";
const VINAPHONE = "VNP";
const GARENA = 4;
const ZING = 5;
const GATE = 7;
const VCOIN = 8;

const CARD_PROCESSING = 0;
const CARD_SUCCESS = 1;
const CARD_FAIL = 2;
const CARD_NOT_FOUND = 3;

var cardTitle = {};
cardTitle[VIETTEL] = "Viettel";
cardTitle[MOBIFONE] = "Mobifone";
cardTitle[VINAPHONE] = "Vinaphone";
cardTitle[GARENA] = "Garena";
cardTitle[ZING] = "Zing";
cardTitle[GATE] = "Gate";
cardTitle[VCOIN] = "VCoin";

const SERVER_STATUS_CODE = {
  0: 'Đóng',
  2: 'Mở',
  3: 'Hot',
  1: 'Bảo trì',
}

@Controller()
export class AuthController {
  constructor(
    private userService: UsersService,
    private authService: AuthService,
    private serverListService: ServerListService,
    private logCardService: LogCardService,
  ) { }

  @Post('/username_check')
  async username_check(@Body() input) {
    var check;
    if((/^[a-zA-Z]{1}([a-zA-Z0-9]|[_@.]){4,19}$/.test(input.Email))) {
      try {
        check = await this.userService.getUserByUserName(input.Email);
      } catch (error) {
        return {state: 1, msg: 'Tài khoản hợp lệ!'};
      }
      
    } else {
      return {state: 0, msg: 'Tài khoản không hợp lệ!'}
    }
    
    if (check) {
      return {state: 0, msg: 'Tài khoản đã tồn tại!'}
    }
    return {state: 1, msg: 'Tài khoản hợp lệ!'};
  }

  @Post('/email_check')
  async email_check(@Body() input) {
    var check;
    // console.log(input.e);
    if((/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.e))) {
      try {
        check = await this.userService.getUserByEmail(input.e);
      } catch (error) {
        return {state: 1, msg: 'Email hợp lệ!'};
      }
      
    } else {
      return {state: 0, msg: 'Email không hợp lệ!'}
    }
    
    if (check) {
      return {state: 0, msg: 'Email đã tồn tại!'}
    }
    return {state: 1, msg: 'Email hợp lệ!'};
  }
  @Post('/phone_check')
  async phone_check(@Body() input) {
    var check;
    // console.log(input.e);
    if((/(84|0[3|5|7|8|9])+([0-9]{8})\b/.test(input.e))) {
      try {
        check = await this.userService.getUserByPhone(input.e);
      } catch (error) {
        return {state: 1, msg: 'Phone hợp lệ!'};
      }
      
    } else {
      return {state: 0, msg: 'Phone không hợp lệ!'}
    }
    
    if (check) {
      return {state: 0, msg: 'Phone đã tồn tại!'}
    }
    return {state: 1, msg: 'Phone hợp lệ!'};
  }

  @Post('/register')
  async registerUser(@Body() input: CreateUserDto) {
    const check = await this.validate(input.email, input.username);
    if (!check) {
      throw new HttpException(
        { message: 'Tài khoản đã tồn tại' },
        HttpStatus.BAD_REQUEST,
      );
    }

    input.password = await this.authService.hashPassword(input.password);
    input.money = 0;
    input.vip_level = 0;
    input.vip_exp = 0;
    input.phone_number = input.phone_number ?? "";
    input.create_at = new Date();
    input.is_exist = true;
    input.is_admin = false;

    delete input.id;

    return this.userService.create(input);
  }

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Request() request): Promise<any> {
    // if(request.body.captcha == request.session.captcha) {
    return this.authService.login(request.user);
    // } else {
    //   console.log(session);
    //   throw new HttpException(request.body.captcha + 'Captcha không chính xác' + session.captcha, HttpStatus.FORBIDDEN);
    // }
  }

  @UseGuards(AuthenticationGuard)
  @Get('current-user')
  async getUserLoggedIn(@Request() request): Promise<UserEntity> {
    var user = await this.userService.findById(request.user.id);
    var censorWord = function (str) {
      return str[0] + "*".repeat(str.length - 3) + str.slice(-2);
    }
    
    var censorEmail = function (email){
      var arr = email.split("@");
      return censorWord(arr[0]) + "@" + censorWord(arr[1]);
    }
    var censorPhone = function (phone_number){
      return censorWord(censorWord(phone_number));
    }
    
    user.email = censorEmail(user.email)
    user.phone_number = censorPhone(user.phone_number)
    return user;
  }

  @UseGuards(AuthenticationGuard)
  @Post('/logout')
  async getUserLogout(@Response() response): Promise<Response> {
    response.setHeader('Set-Cookie', this.authService.getCookieForLogOut());
    response.clearCookie('access_token');
    response.clearCookie('token');

    return response.sendStatus(200);
  }

  @UseGuards(AuthenticationGuard)
  @SkipThrottle()
  @Get('create-login/:id')
  async createLoginServerId(@Param('id') id: number, @Request() request): Promise<string> {

    var server = await this.serverListService.getServerDetail(id);

    var userDetail = await this.userService.findById(request.user.id);
    if (SERVER_OPEN == server.Status || SERVER_HOT == server.Status || userDetail.vip_level >= 12) {
      try {
        var keyrand = uuid().toLowerCase();

        var timeNow = (+ new Date() / 1000).toFixed(0).toString();

        var url = `${server.RequestUrl}CreateLogin.aspx?content=${request.user.name.toLowerCase()}|${keyrand}|${timeNow}|${await this.authService.hashPassword(request.user.name.toLowerCase() + keyrand + timeNow + server.KeyRequest)}`;

        const response = await axios.get(url);

        var status = response.data;
        if (status == "0") {
          return `${server.FlashUrl}Loading.swf?user=${request.user.name.toLowerCase()}&key=${keyrand}&v=104&rand=92386938&config=${server.ConfigUrl}`;
        }

        return status;
      } catch (e) {
        console.log(e);
        console.log(request.user);
        return null;
      }
    }
    return `Máy chủ hiện đã ${SERVER_STATUS_CODE[server.Status]}`;
  }

  @UseGuards(AuthenticationGuard)
  @SkipThrottle()
  @Get('create-flashvars/:id')
  async createFlashVars(@Param('id') id: number, @Request() request): Promise<any> {

    var server = await this.serverListService.getServerDetail(id);

    var userDetail = await this.userService.findById(request.user.id);
    if (SERVER_OPEN == server.Status || SERVER_HOT == server.Status || userDetail.vip_level >= 12) {
      try {
        var keyrand = uuid().toLowerCase();

        var timeNow = (+ new Date() / 1000).toFixed(0).toString();

        var url = `${server.RequestUrl}CreateLogin.aspx?content=${request.user.name.toLowerCase()}|${keyrand}|${timeNow}|${await this.authService.hashPassword(request.user.name.toLowerCase() + keyrand + timeNow + server.KeyRequest)}`;

        const response = await axios.get(url);

        var status = response.data;
        if (status == "0") {
          var swfPath = server.FlashUrl + 'Loading.swf';
          var flashvars = {
            user: request.user.name.toLowerCase(),
            key: keyrand,
            v: "104",
            rand: "92386938",
            config: server.ConfigUrl
          };
          return { swfPath, flashvars };
          // return `${server.FlashUrl}Loading.swf?user=${request.user.name.toLowerCase()}&key=${keyrand}&v=104&rand=92386938&config=${server.ConfigUrl}`;
        }


        return status;
      } catch (e) {
        console.log(e);
        console.log(request.user);
        return null;
      }
    }
    return `Máy chủ hiện đã ${SERVER_STATUS_CODE[server.Status]}`;
  }

  @UseGuards(AuthenticationGuard)
  @SkipThrottle()
  @Get('create-flash-link/:id')
  async createFlashLinkWithSv(@Param('id') id: number, @Request() request): Promise<string> {
    var server = await this.serverListService.getServerDetail(id);

    var userDetail = await this.userService.findById(request.user.id);
    if (SERVER_OPEN == server.Status || SERVER_HOT == server.Status || userDetail.vip_level >= 12) {
      var keyrand = uuid().toLowerCase();

      var timeNow = (+ new Date() / 1000).toFixed(0).toString();

      var url = `${server.RequestUrl}CreateLogin.aspx?content=${request.user.name.toLowerCase()}|${keyrand}|${timeNow}|${await this.authService.hashPassword(request.user.name.toLowerCase() + keyrand + timeNow + server.KeyRequest)}`;

      const response = await axios.get(url);

      var status = response.data;
      if (status = "0") {
        return `${server.FlashUrl}Loading.swf|user=${request.user.name.toLowerCase()}&key=${keyrand}&v=104&rand=92386938&config=${server.ConfigUrl}`;
      }

      return status;
    }

    return `Máy chủ hiện đã ${SERVER_STATUS_CODE[server.Status]}`;
  }

  @UseGuards(AuthenticationGuard)
  @Post('serverlist')
  async getServerList(@Request() request): Promise<string> {// for launcher
    var KQ = '';
    var x = 32;
    var y = 18;
    var serverList = await this.serverListService.getServerList();
    serverList.forEach(element => {
      KQ += `${element.id},${element.Name},${x},${y}|`;
      // KQ;
      x += 208;
    });
    // while($svInfo = sqlsrv_fetch_array($loadserver, SQLSRV_FETCH_ASSOC)) {
    //echo '<option value="'.$svInfo['ServerID'].'">'.$svInfo['ServerName'].'</option>';

    // }
    return KQ;
  }

  @UseGuards(AuthenticationGuard)
  @Get('check-open')
  async getCheckOpen(@Request() request): Promise<string> {// for launcher
    return 'True';
  }

  @UseGuards(AuthenticationGuard)
  @Post('update')
  async update(@Request() request): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    var oldPassMd5 = await this.authService.hashPassword(request.body.oldpassword);

    if (user.password == oldPassMd5) {
      var update = _.pick(request.body, 'password');
      update.password = await this.authService.hashPassword(update.password);
      await this.userService.update(user, update);
      return 'Đổi thông tin thành công';
    }

    return 'Dữ liệu không hợp lệ';
  }

  @UseGuards(AuthenticationGuard)
  @Post('change-password')
  async changePassword(@Request() request): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    var oldPassMd5 = await this.authService.hashPassword(request.body.oldPassword);
    let phoneNumber = request.body.phoneNumber;

    if (phoneNumber != '' && user.phone_number == phoneNumber && user.password == oldPassMd5) {
      var update = _.pick(request.body, 'password');
      if(update.password == request.body.password_confirmation) {
        update.password = await this.authService.hashPassword(update.password);
        await this.userService.update(user, update);
        return {msg: 'Đổi thông tin thành công'};
      } else {
        return {msg: 'Mật khẩu không khớp'};
      }
      
    }

    return {msg: 'Dữ liệu không hợp lệ'};
  }

  @UseGuards(AuthenticationGuard)
  @Post('change-phone')
  async changePhone(@Request() request): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    let phoneNumber = request.body.phoneNumber;
    if (user.phone_number == request.body.oldPhone) {
      var update = _.pick(request.body, 'phone_number');
      if(phoneNumber == request.body.phoneNumber_confirmation) {
        update.phone_number = request.body.phoneNumber_confirmation;
        await this.userService.update(user, update);
        return {msg: 'Đổi thông tin thành công'};
      } else {
        return {msg: 'Số điện thoại không khớp'};
      }
      
    }

    return {msg: 'Dữ liệu không hợp lệ'};
  }

  @Post('/forgot-password')
  async forgotPassword(@Body() input, @Response() response) {
    const user = await this.userService.getUserByUserName(input.username);
    if (user) {
      if (input.email && input.email == user.email) {
        var update = _.pick(input, 'password');
        update.password = await this.authService.hashPassword(update.password);
        await this.userService.update(user, update);
        response.status(200).send('Quên mật khẩu thành công!');
        return 'Quên mật khẩu thành công!';
      }
      return response.status(422).send('Email không chính xác');
      return 'Email không chính xác';
    } else {
      return response.status(401).send('Tài khoản không tồn tại');
      // return "Tài khoản không tồn tại";
    }
  }

  @Get('/captcha')
  @Header('content-type', 'image/svg+xml')
  async captcha(@Request() request, @Session() session: Record<string, any>): Promise<any> {
    var svgCaptcha = require('svg-captcha');

    var captcha = svgCaptcha.create({
      size: 3
    });
    session.captcha = captcha.text;
    // console.log(captcha);
    return captcha.data;
  }

  @UseGuards(LocalAuthGuard)
  @Get('/valid-captcha')
  async validCaptcha(@Request() request): Promise<any> {
    return request.session.captcha
  }

  @UseGuards(AuthenticationGuard)
  @Post('chargeMoney')
  async chargeMoney(@Request() request): Promise<any> {
    var status = 0;
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    var svId = request.body.server_id;

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return {msg: 'Vui lòng chọn server', status: 'error'};
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    var connection = await createConnection({
      name: `dbPlayer${svId}${+(new Date())}`,
      type: 'mssql',
      host: server.DataSource,
      username: server.UserID,
      password: server.Password,
      database: server.Catalog,
      entities: ['dist/**/*.entity.js'],
      migrations: ['dist/databases/migrations/*.js'],
      cli: { migrationsDir: 'src/databases/migrations' },
      synchronize: false,
      extra: {
        trustServerCertificate: true,
      },
      ...portOptions
    });
    // connection.createQueryRunner();
    const queryRunner = await connection.createQueryRunner();
    var total = await queryRunner.manager.query(
      `SELECT COUNT(*) as total FROM Charge_Money`
    );
    var userDetail = await queryRunner.manager.query(
      `select UserID,NickName from Sys_Users_Detail where UserName = '${request.user.name}'`
    );
    var chargeID = total[0] ? total[0].total : 0;
    var playerID = userDetail[0] ? userDetail[0].UserID : 0;
    var NickName = userDetail[0] ? userDetail[0].NickName : 0;
    chargeID = await this.authService.hashPassword(chargeID.toString());
    var money = parseInt(request.body.money);

    if (isNaN(money)) {
      money = 0;
    }

    var resultText = 'Đổi xu thành công!';

    if (user.money >= money) {
      var update = _.pick(user, 'money');
      update.money -= money;
      await this.userService.update(user, update);
      var xuReceive = Math.round(money * 1);
      if (money > 0) {
        var result = await queryRunner.manager.query(
          `INSERT INTO Charge_Money
            ([ChargeID]
            ,[UserName]
            ,[Money]
            ,[CanUse]
            ,[PayWay]
            ,[NeedMoney]
            ,[NickName])
          VALUES
            ('${chargeID}'
            ,N'${request.user.name}'
            ,${xuReceive}
            ,1
            ,0
            ,0
            ,N'${NickName}'
            )`
        );

        var url = `${server.RequestUrl}/ChargeToUser.aspx?userID=${playerID}&chargeID=${chargeID}`;

        const response = await axios.get(url);

        resultText = 'Chuyển xu thành công!'       
      } else {
        resultText = 'Dữ liệu không hợp lệ';
      }
    } else {
      resultText = 'Số dư không đủ';
    }



    connection.close();


    return {msg: resultText};
  }

  async validate(email: string, username: string) {
    try {
      const users = await this.userService.geUsersByEmail(email, username);
      return users.length <= 0;
    } catch (e) {
      return false;
    }
  }

  @Get('/launcher/version.xml')
  async launcherVersion(@Request() request): Promise<any> {
    return `<?xml version="1.0" encoding="utf-8"?>
    <item>
      <version>${LAUNCHER_VERSION}</version>
      <url>http://newgun.net/Launcher V2.5.zip</url>
      <urlfast>http://newgun.net/Launcher V2.5.zip</urlfast>  
      <changelog>http://newgun.net:3005/api/launcher/infoupdate2.html</changelog>
      <mandatory>true</mandatory>
    </item>`;
  }

  @Get('/launcher/infoupdate2.html')
  async launcherInfo(@Request() request): Promise<any> {
    return `

    <style>
    body
    {
    background-color: orange;
    }
    </style>
    <body><font color=black>
    - Nhẹ hơn, fix 1 số lỗi <br>
    
    
    </body>`;
  }

  @UseGuards(AuthenticationGuard)
  @Post('/recharge')
  async recharge(@Body() input, @Request() request) {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }

    var rate = 1.0;
    switch (input.card_type) {
      case VIETTEL:
        rate = 1.0;
        break;
      case MOBIFONE:
        rate = 1.0;
        break;
      case VINAPHONE:
        rate = 1.0;
        break;
      case GARENA:
        rate = 1.0;
        break;
      case ZING:
        rate = 1.0;
        break;
      case GATE:
        rate = 1.0;
        break;
      case VCOIN:
        rate = 1.0;
        break;
      default:
        rate = 0.0;
        break;
    }

    if (this.ValidateCard(input.card_type, input.card_seri, input.card_code) !== true) {
      return this.ValidateCard(input.card_type, input.card_seri, input.card_code);
    }

    if (rate <= 0) {
      console.log((input.card_type));
      return 'Loại thẻ không hợp lệ';
    }

    var money = 0;
    money = parseInt(input.money);
    switch (parseInt(input.money)) {
      case 10000:
        break;
      case 20000:
        break;
      case 30000:
        break;
      case 40000:
        break;
      case 50000:
        break;
      case 100000:
        break;
      case 200000:
        break;
      case 300000:
        break;
      case 5000000:
        break;
      case 1000000:
        break;
      default:
        money = 0;
        break;
    }

    if (money <= 0) {
      return 'Mệnh giá không hợp lệ';
    }
    var whereClause = {
      card_type: input.card_type,
      card_code: input.card_code,
      card_seri: input.card_seri,
      money: input.money,
    };

    var cardInfo = await this.logCardService.getRepository().findOne(whereClause);
    if (cardInfo) {
      return 'Thẻ đã được nạp trên hệ thống, vui lòng thử lại sau!';
    } else {
      var url = `https://trumthe247.com/restapi/charge`;
      var postParams = {
        // access_token: "AQrvfPgjqtKoy4puXVI2YwXszWLkAJsn", 
        // code: input.card_code,
        // seri: input.card_seri,
        // money: input.money,
        // typeCard: input.card_type
        card: input.card_type,
        amount: input.money,
        serial: input.card_seri,
        pin: input.card_code,
        api_key: "d74855606a76c8d2aea88866319420e7",
        api_secret: "0aab6434fcfbb5299547e0f776324be6",
        content: "NEWGUN-" + request.user.id,
        referer: "newgun.net"
      };

      var form = new FormData();
      Object.keys(postParams).map(item => {
        form.append(item, postParams[item]);
      })
      // const response = await axios.post(url, { params: {...postParams}});
      const response = await axios({
        method: 'post',
        url: url,
        data: form,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Referer": "http://newgun.net/",
        },
      });
      console.log(response);
      var resData = response.data;
      // if(false){

      //   var cardInput = new LogCardEntity();
      //   cardInput.card_name = cardTitle[input.card_type];
      //   cardInput.card_code = input.card_code;
      //   cardInput.card_seri = input.card_money;
      //   cardInput.card_type = input.card_type;
      //   cardInput.money = parseInt(resData.amount);
      //   cardInput.note = '';
      //   cardInput.status = CARD_SUCCESS;
      //   cardInput.user_id = request.user.id;

      //   var update = _.pick(user, 'money');
      //   update.money += parseInt(resData.amount);
      //   await this.userService.update(user, update);

      //   this.logCardService.getRepository().save(cardInput);

      //   return 'Chúc mừng bạn nạp thẻ thành công với mệnh giá '+ resData.amount;
      // } else 
      if (resData.status == "" || resData.status == null || resData.status == undefined) {
        return 'Có lỗi trong quá trình gửi thẻ lên hệ thống!'
      }
      else if (resData.status == 1) {
        var cardInput = new LogCardEntity();
        cardInput.card_name = cardTitle[input.card_type];
        cardInput.card_code = input.card_code.toString();
        cardInput.card_seri = input.card_seri.toString();
        cardInput.card_type = input.card_type.toString();
        cardInput.money = money;
        cardInput.create_at = new Date();
        cardInput.note = '';
        cardInput.status = CARD_PROCESSING;
        cardInput.user_id = request.user.id;

        this.logCardService.getRepository().save(cardInput);
        return 'Thẻ đang được xử lý vui lòng đợi trong giây lát';
      } else {
        return resData.desc;
      }
    }
  }

  ValidateCard(card_type, serial, pin) { //Hàm kiểm tra định dạng thẻ.
    if (card_type == 'VTT' || card_type == 'VTT2') {
      if (serial.length != 11 && serial.length != 14)
        return 'Số serial thẻ không đúng.';

      if (pin.length != 13 && pin.length != 15)
        return 'Mã thẻ không đúng.';
    }

    if (card_type == 'VMS' || card_type == 'VMS2') {
      if (serial.length != 15)
        return 'Số serial thẻ không đúng.';

      if (pin.length != 12)
        return 'Mã thẻ không đúng.';
    }

    if (card_type == 'VNP' || card_type == 'VNP2') {
      if (serial.length != 14)
        return 'Số serial thẻ không đúng.';

      if (pin.length != 14)
        return 'Mã thẻ không đúng.';
    }

    return true;
  }

  @Post('/callback/:id')
  async callback(@Param('id') id: number, @Body() input) {
    if (id == 6969696911212) {
      // var card = input.card;
      var card_type = input.card_data.card_type;
      var amount = input.card_data.amount;
      var serial = input.card_data.serial;
      var pin = input.card_data.pin;
      // var access_token = input.access_token;
      var status = input.status;
      var desc = input.desc;
      var api_key = input.api_key;
      var api_secret = input.api_secret;
      var notFoundCard = false;
      var result = "false";
      // var transaction_id = input.transaction_id;
      console.log(input);
      // console.log({card, amount, serial, pin, access_token, status, desc, transaction_id});
      // Thẻ đúng 

      if (api_key == 'd74855606a76c8d2aea88866319420e7' && api_secret == '0aab6434fcfbb5299547e0f776324be6') {
        if (status == 1) {
          // select ngược trong database theo serial & pin hoặc transaction_id để lấy thông tin  thẻ đã nạp 
          // update lại status của thẻ nạp đó

          var whereClause = {
            // card_type: card_type,
            card_code: pin,
            card_seri: serial,
            // money: amount,
          };

          var cardInfo = await this.logCardService.getRepository().findOne(whereClause);
          if (!cardInfo) {
            notFoundCard = true;
          } else {
            const user = await this.userService.findById(cardInfo.user_id);
            if (!user) {
              throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
            }

            var update = _.pick(user, 'money');
            update.money += parseInt(amount);
            await this.userService.update(user, update);

            var updateCard = _.pick(cardInfo, 'status');
            updateCard.status = CARD_SUCCESS;
            await this.logCardService.getRepository().update(cardInfo, updateCard);
            result = 'ok';
          }
        } else {
          // thẻ sai
          var whereFailClause = {
            card_type: card_type,
            card_code: pin,
            card_seri: serial
          };
          var cardInfo = await this.logCardService.getRepository().findOne(whereFailClause);
          if (!cardInfo) {
            notFoundCard = true;
          } else {
            var updateCard = _.pick(cardInfo, 'status');
            updateCard.status = CARD_FAIL;
            await this.logCardService.getRepository().update(cardInfo, updateCard);
          }

          result = 'card wrong ok';
        }
      } else {
        result = 'wrong api key & secret!';
      }
      if (notFoundCard) {
        result = "not found card";
        var cardInput = new LogCardEntity();
        cardInput.card_name = cardTitle[input.card_type];
        cardInput.card_code = pin.toString();
        cardInput.card_seri = serial.toString();
        cardInput.card_type = card_type.toString();
        cardInput.money = amount;
        cardInput.create_at = new Date();
        cardInput.note = '';
        cardInput.status = CARD_NOT_FOUND;//card WRONG
        cardInput.user_id = 0;

        this.logCardService.getRepository().save(cardInput);
      }

      return result;

    }
  }

  @UseGuards(AuthenticationGuard)
  @Post('getCharacters')
  async getCharacters(@Request() request): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    var svId = request.body.server_id;

    if (!svId || isNaN(svId)) {
      return '';
    }

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return '';
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    try {
      var connection = await createConnection({
        name: `dbPlayer${svId}${+(new Date())}`,
        type: 'mssql',
        host: server.DataSource,
        username: server.UserID,
        password: server.Password,
        database: server.Catalog,
        entities: ['dist/**/*.entity.js'],
        migrations: ['dist/databases/migrations/*.js'],
        cli: { migrationsDir: 'src/databases/migrations' },
        synchronize: false,
        extra: {
          trustServerCertificate: true,
        },
        ...portOptions
      });

      const queryRunner = await connection.createQueryRunner();
      var total = await queryRunner.manager.query(
        `SELECT UserID, NickName, Grade FROM Sys_Users_Detail where UserName = '${user.username}'`
      );

      if (total && total.length > 0) {
        total = total.map(item => Object.values(item).join(','))
      } else {
        total = [];
      }


      connection.close();

      return total.join('|');
    } catch (error) {
      return '';
    }

  }

  @UseGuards(AuthenticationGuard)
  @Post('player-nickname')
  async playernickname(@Request() request): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    var svId = request.body.serverId;

    if (!svId || isNaN(svId)) {
      return '';
    }

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return '';
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    try {
      var connection = await createConnection({
        name: `dbPlayer${svId}${+(new Date())}`,
        type: 'mssql',
        host: server.DataSource,
        username: server.UserID,
        password: server.Password,
        database: server.Catalog,
        entities: ['dist/**/*.entity.js'],
        migrations: ['dist/databases/migrations/*.js'],
        cli: { migrationsDir: 'src/databases/migrations' },
        synchronize: false,
        extra: {
          trustServerCertificate: true,
        },
        ...portOptions
      });

      const queryRunner = await connection.createQueryRunner();
      var total = await queryRunner.manager.query(
        `SELECT UserID as id, NickName as nickname, Grade FROM Sys_Users_Detail where UserName = '${user.username}'`
      );

      connection.close();

      return total;
    } catch (error) {
      return '';
    }
  }

  @Get('getActives/:svId')
  async getActives(@Param('svId') svId: number, @Request() request): Promise<any> {
    if (!svId || isNaN(svId)) {
      return '';
    }

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return '';
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    try {
      var connection = await createConnection({
        name: `dbPlayer${svId}${+(new Date())}`,
        type: 'mssql',
        host: server.DataSource,
        username: server.UserID,
        password: server.Password,
        database: 'Project_Game34',
        entities: ['dist/**/*.entity.js'],
        migrations: ['dist/databases/migrations/*.js'],
        cli: { migrationsDir: 'src/databases/migrations' },
        synchronize: false,
        extra: {
          trustServerCertificate: true,
        },
        ...portOptions
      });

      const queryRunner = await connection.createQueryRunner();
      var total = await queryRunner.manager.query(
        `SELECT [ActiveID], [Title] FROM [dbo].[Active] Where CanCreateCode = 1`
      );

      return total;
    } catch (error) {
      return '';
    }
  }

  @Get('getCodeActive/:svId/:id')
  async getCodeActive(@Param('svId') svId: number, @Param('id') activeId: number, @Request() request): Promise<any> {
    if (!svId || isNaN(svId)) {
      return '';
    }

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return '';
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    try {
      var connection = await createConnection({
        name: `dbPlayer${svId}${+(new Date())}`,
        type: 'mssql',
        host: server.DataSource,
        username: server.UserID,
        password: server.Password,
        database: server.Catalog,
        entities: ['dist/**/*.entity.js'],
        migrations: ['dist/databases/migrations/*.js'],
        cli: { migrationsDir: 'src/databases/migrations' },
        synchronize: false,
        extra: {
          trustServerCertificate: true,
        },
        ...portOptions
      });

      const queryRunner = await connection.createQueryRunner();
      var activeNumber = await queryRunner.manager.query(
        `SELECT TOP 1 * FROM [dbo].[Active_Number] where PullDown = 0 and GetByBot = 0`
      );
      if (activeNumber.length > 0) {
        await queryRunner.manager.query(
          `UPDATE [dbo].[Active_Number] set GetByBot = 1 where AwardID = '${activeNumber[0].AwardID}'`
        );
        return { status: 'success', code: activeNumber[0] };
      } else {
        return { status: 'error', code: null };
      }
    } catch (error) {
      console.log(error)
      return '';
    }
  }

  @Post('get_rank')
  async get_rank(@Request() request): Promise<any> {
    var svId = request.body.sid;
    var type = request.body.type;

    var server = await this.serverListService.getServerDetail(svId);

    if (!server) {
      return [];
    }

    var portOptions = {};
    if (server.Port && server.Port > 0) {
      portOptions = { port: server.Port }
    }
    var connection = await createConnection({
      name: `dbPlayer${svId}${+(new Date())}`,
      type: 'mssql',
      host: server.DataSource,
      username: server.UserID,
      password: server.Password,
      database: server.Catalog,
      entities: ['dist/**/*.entity.js'],
      migrations: ['dist/databases/migrations/*.js'],
      cli: { migrationsDir: 'src/databases/migrations' },
      synchronize: false,
      extra: {
        trustServerCertificate: true,
      },
      ...portOptions
    });
    // connection.createQueryRunner();
    const queryRunner = await connection.createQueryRunner();

    var sql = '';

    switch(parseInt(type)) {
      case 1://Lực chiến
        sql = `select TOP 10 UserID, NickName, FightPower, Grade from Sys_Users_Detail where IsExist = 1 order by FightPower desc`;
        break;
      case 2://Level
        sql = `select TOP 10 UserID, NickName, Grade, GP from Sys_Users_Detail where IsExist = 1 order by GP desc`;
        break;
      case 3://Online
        sql = `select TOP 10 UserID, NickName, OnlineTime from Sys_Users_Detail where IsExist = 1 order by OnlineTime desc`;
        break;
      case 4://Hấp dẫn
        sql = `select TOP 10 UserID, NickName, charmGP from Sys_Users_Detail where IsExist = 1 order by charmGP desc`;
        break;
		case 5://tieu xu
		sql = `SELECT TOP 10 NickName , Sum ([Xu]) as XuTieu FROM Sys_Users_LogTieuxu group by [NickName]  Order by [XuTieu] desc`;
		break;
		case 6://tieu xu
		sql = `SELECT TOP 10 NickName , Sum ([money]) as Xunap FROM Charge_Money group by [NickName]  Order by [Xunap] desc`;
		break;
    }

    var data = await queryRunner.manager.query(
      sql
    );

    connection.close();

    return data;
  }

  @Post('get_new_server')
  async get_new_server(@Request() request): Promise<any> {// for launcher
    var data = [];
    var serverList = await this.serverListService.getServerList();
    serverList.forEach(element => {
      // element.id},${element.Name
      data.push({
          sid:element.id,
          serverid:element.id,
          gid:element.id,
          servername: element.Name,
          status: element.Status,
          platform_id: "1",
          platform_name:element.Name,
          line:element.id,
          sid_h:element.id,
          start_time:"1668135000",
          unstart:0,
          url:""
      });
    });
    // while($svInfo = sqlsrv_fetch_array($loadserver, SQLSRV_FETCH_ASSOC)) {
    //echo '<option value="'.$svInfo['ServerID'].'">'.$svInfo['ServerName'].'</option>';

    // }
    return data;
  }

  @Post('news')
  async news(@Request() request): Promise<any> {
    return '';
  }

  @Post('get_log_card')
  @UseGuards(AuthenticationGuard)
  async get_log_card(@Request() request): Promise<any> {
    var whereClause = {
      user_id: request.user.id,
    };
    return this.logCardService.getRepository().find(whereClause)
  }

  @UseGuards(AuthenticationGuard)
  @Post('search_account')
  async search_account(@Request() request, @Response() response): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    if(user.is_admin){

    var sql = `select * from [user] where [user].username like '%${request.body.username}%'`;

    var data = await this.userService.getRepository().query(
      sql
    );
      return response.status(200).send(data);
    } else {
      return response.status(401).send('Không đủ quyền hạn');
    }
  }

  @UseGuards(AuthenticationGuard)
  @Post('add-coin')
  async add_coin(@Request() request, @Response() response): Promise<any> {
    const user = await this.userService.findById(parseInt(request.user.id, 0));
    if (!user) {
      throw new HttpException("User don't exists", HttpStatus.NOT_FOUND);
    }
    if(user.is_admin){
      var {username, is_log, coin} = request.body;
      if(isNaN(parseInt(coin, 0))) {
        return response.status(422).send('Coin không hợp lệ!');
      } else {
        var logStatus = 'Không log'
        const userAdd = await this.userService.getUserByUserName(username);
        if (userAdd) {
          var update = _.pick(userAdd, 'money');
          update.money += parseInt(coin);
          await this.userService.update(userAdd, update);
          if(is_log != 'false' && is_log) {
            var cardInput = new LogCardEntity();
            cardInput.card_name = 'Bank';
            cardInput.card_code ='Bank';
            cardInput.card_seri = 'Bank';
            cardInput.card_type = 'Bank';
            cardInput.money = coin;
            cardInput.create_at = new Date();
            cardInput.note = '';
            cardInput.status = CARD_SUCCESS;
            cardInput.user_id = userAdd.id;
            var logStatus = 'Có log'
            this.logCardService.getRepository().save(cardInput);
          }

          return response.status(200).send(`Cộng ${coin} coin thành công cho tài khoản ${username} (${logStatus})!`);
        } else {
          return response.status(422).send('Tài khoản không tồn tại');
          // return "Tài khoản không tồn tại";
        }
      }
      return response.status(200).send({username, is_log, coin});
    } else {
      return response.status(401).send('Không đủ quyền hạn');
    }
  }
}
