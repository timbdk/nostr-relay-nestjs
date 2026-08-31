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
  // Ring buffer of recent checkpoints, replayed to each new subscriber so a
  // reconnecting pipeline monitor cannot miss events that fired during the gap.
  // Subscribers pass ?since=<ts> to receive only the events newer than what
  // they already saw — stale events from before the connection are never replayed.
  private readonly recentCheckpoints: { ts: number; payload: string }[] = [];
  private readonly maxBuffer = 500;

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

    this.wss.on('connection', (ws: any, req: any) => {
      this.clients.add(ws);
      this.logger.debug(
        `[testing] Stream client connected (${this.clients.size} total)`,
      );

      // Ack first (marks subscription) then replay only the checkpoints the
      // subscriber has not seen yet (newer than the ?since= query parameter).
      const since = this.parseSince(req?.url);
      const replay = this.recentCheckpoints
        .filter((c) => since === undefined || c.ts > since)
        .map((c) => c.payload);
      try {
        ws.send(JSON.stringify({ type: 'ack', buffer: replay }));
      } catch { /* ignore */ }

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

  private parseSince(url?: string): number | undefined {
    if (!url) return undefined;
    const query = String(url).split('?')[1];
    if (!query) return undefined;
    const since = new URLSearchParams(query).get('since');
    if (since === null) return undefined;
    const parsed = Number.parseInt(since, 10);
    return Number.isFinite(parsed) ? parsed : undefined;
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
    if (!this.enabled) return;

    const payload = JSON.stringify({
      type: 'checkpoint',
      step,
      timestamp: Date.now(),
      service: 'relay',
      data,
    });

    this.recentCheckpoints.push({ ts: Date.now(), payload });
    if (this.recentCheckpoints.length > this.maxBuffer) {
      this.recentCheckpoints.shift();
    }

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
