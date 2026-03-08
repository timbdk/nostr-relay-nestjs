import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import { KyselyDb } from './modules/repositories/kysely-db';

@Controller('health')
export class AppController {
    constructor(private readonly db: KyselyDb) { }

    @Get()
    async check(@Res() res: Response) {
        try {
            const result = await this.db.isHealthy();
            if (result === true) {
                return res.status(200).send('OK');
            }
            return res.status(503).send(`Database Offline: ${result}`);
        } catch (err: any) {
            return res.status(500).send(`Internal Error: ${err.message}`);
        }
    }
}
