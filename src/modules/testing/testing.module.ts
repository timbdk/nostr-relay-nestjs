import { Module, forwardRef } from '@nestjs/common'
import { TestingCheckpointService } from './testing-checkpoint.service'
import { TestingController } from './testing.controller'
import { NostrModule } from '../nostr/nostr.module'

/**
 * Testing Module — Conditionally loaded when NODE_ENV=testing.
 *
 * Provides TestingCheckpointService which manages its own raw
 * WebSocket server (bypassing the NestJS WsAdapter) and TestingController
 * for test harness cache reset.
 */
@Module({
  imports: [forwardRef(() => NostrModule)],
  controllers: [TestingController],
  providers: [TestingCheckpointService],
  exports: [TestingCheckpointService],
})
export class TestingModule { }
