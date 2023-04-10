import { MysqlConnectionOptions } from 'typeorm/driver/mysql/MysqlConnectionOptions';
import { SqlServerConnectionOptions } from 'typeorm/driver/sqlserver/SqlServerConnectionOptions';

const config: SqlServerConnectionOptions = {
  type: 'mssql',
  host: '103.161.180.252',
  port: 1743,
  username: 'sa',
  password: 'gunhuyenthoai',
  database: 'VinhDDT',
  entities: ['dist/**/*.entity.js'],
  migrations: ['dist/databases/migrations/*.js'],
  cli: { migrationsDir: 'src/databases/migrations' },
  synchronize: false,
  extra: {
    trustServerCertificate: true,
  }
};

export default config;
