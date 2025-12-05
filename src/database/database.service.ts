// src/database/database.service.ts
import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection } from 'mongoose';

@Injectable()
export class DatabaseService implements OnModuleInit {
  private readonly logger = new Logger(DatabaseService.name);

  constructor(@InjectConnection() private readonly connection: Connection) {}

  async onModuleInit() {
    if (this.connection.readyState === 1) {
      this.logger.log('✅ MongoDB Connected Successfully');
    } else {
      this.logger.error('❌ MongoDB Connection Failed');
    }
  }

  getConnection(): Connection {
    return this.connection;
  }
}
