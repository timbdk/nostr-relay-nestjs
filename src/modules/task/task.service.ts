import { Injectable } from '@nestjs/common';
import { Cron, CronExpression, Interval } from '@nestjs/schedule';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { MetricService } from '../metric/metric.service';
import { EventRepository } from '../repositories/event.repository';
import { WotService } from '../wot/wot.service';

@Injectable()
export class TaskService {
  constructor(
    @InjectPinoLogger(TaskService.name)
    private readonly logger: PinoLogger,
    private readonly eventRepository: EventRepository,
    private readonly metricService: MetricService,
    private readonly wotService: WotService,
  ) {}

  @Interval(600000) // 10 minutes
  async deleteExpiredEvents() {
    try {
      const affected = await this.eventRepository.deleteExpiredEvents();
      this.logger.info(`Deleted ${affected} expired events`);
    } catch (err: any) {
      this.logger.warn({ err }, 'Failed to delete expired events');
    }
  }

  @Cron(CronExpression.EVERY_HOUR)
  async recordMetric() {
    try {
      this.metricService.recordMetric();
    } catch (err: any) {
      this.logger.warn({ err }, 'Failed to record metrics');
    }
  }

  @Interval(3600000) // 1 hour
  async refreshWot() {
    try {
      await this.wotService.refreshWot();
    } catch (err: any) {
      this.logger.warn({ err }, 'Failed to refresh WOT');
    }
  }
}
