import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { WebSocket, WebSocketServer } from 'ws';

const TESTING_PORT = parseInt(process.env.VERITY_RELAY_TESTING_PORT || '9100', 10);

/**
 * Testing Checkpoint Service — Broadcasts pipeline state transitions
 * to connected WebSocket clients for distributed test tracing.
 *
 * Only active when NODE_ENV=testing. All calls are no-ops otherwise.
 *
 * Uses a raw ws.Server instead of NestJS @WebSocketGateway to avoid
 * conflicts with the relay's custom WsAdapter (which uses a Nostr
 * protocol preprocessor that would reject testing stream messages).
 */
@Injectable()
export class TestingCheckpointService implements OnModuleInit, OnModuleDestroy {
  private readonly clients = new Set<WebSocket>();
  private readonly enabled = process.env.NODE_ENV === 'testing';
  private wss: WebSocketServer | null = null;

  constructor(
    @InjectPinoLogger(TestingCheckpointService.name)
    private readonly logger: PinoLogger,
  ) { }

  onModuleInit() {
    if (!this.enabled) return;

    this.wss = new WebSocketServer({
      port: TESTING_PORT,
      path: '/testing/stream',
    });

    this.wss.on('connection', (ws: any) => {
      this.clients.add(ws);
      this.logger.debug(
        `[testing] Stream client connected (${this.clients.size} total)`,
      );

      ws.on('close', () => {
        this.clients.delete(ws);
        this.logger.debug(
          `[testing] Stream client disconnected (${this.clients.size} remaining)`,
        );
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });

    this.wss.on('listening', () => {
      this.logger.info(
        `[testing] Checkpoint stream listening on port ${TESTING_PORT}`,
      );
    });
  }

  onModuleDestroy() {
    if (this.wss) {
      for (const client of this.clients) {
        try { client.close(); } catch { /* ignore */ }
      }
      this.clients.clear();
      this.wss.close();
      this.wss = null;
    }
  }

  /**
   * Broadcast a checkpoint event to all connected testing clients.
   *
   * No correlationId at the relay level — each relay instance is per-worker
   * and isolated, so the test runner matches on step name alone.
   *
   * @param step - Checkpoint step name (e.g. 'relay.request.received')
   * @param data - Optional metadata (kind, pubkey, id, pTags)
   */
  broadcast(step: string, data?: Record<string, any>): void {
    if (!this.enabled || this.clients.size === 0) return;

    const payload = JSON.stringify({
      type: 'checkpoint',
      step,
      timestamp: Date.now(),
      service: 'relay',
      data,
    });

    for (const client of this.clients) {
      try {
        if (client.readyState === WebSocket.OPEN) {
          client.send(payload);
        }
      } catch {
        this.clients.delete(client);
      }
    }

    this.logger.debug(
      `[testing] Broadcast: ${step} (${this.clients.size} clients)`,
    );
  }
}
