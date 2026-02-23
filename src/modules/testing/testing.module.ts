import { Module } from '@nestjs/common';
import { TestingCheckpointService } from './testing-checkpoint.service';

/**
 * Testing Module — Conditionally loaded when NODE_ENV=testing.
 *
 * Provides TestingCheckpointService which manages its own raw
 * WebSocket server (bypassing the NestJS WsAdapter).
 *
 * Exported so other modules (e.g. NostrModule) can inject the service.
 */
@Module({
  providers: [TestingCheckpointService],
  exports: [TestingCheckpointService],
})
export class TestingModule { }
