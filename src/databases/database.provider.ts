import { createConnection } from 'typeorm';
import config from '../orm-config';

export const databaseProviders = [
  {
    provide: 'DATABASE_CONNECTION',
    useFactory: async () => await createConnection(config),
  },
];

// const config: SqlServerConnectionOptions = {
//   type: 'mssql',
//   host: 'XayKPmtN',
//   // port: 1433,
//   username: 'sa',
//   password: 'abc@123',
//   database: 'VinhDDT',
//   entities: ['dist/**/*.entity.js'],
//   migrations: ['dist/databases/migrations/*.js'],
//   cli: { migrationsDir: 'src/databases/migrations' },
//   synchronize: false,
//   extra: {
//     trustServerCertificate: true,
//   }
// };
