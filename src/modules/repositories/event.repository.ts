import { Injectable } from '@nestjs/common'
import {
  Event,
  EventUtils,
  Filter,
  getTimestampInSeconds,
  EventRepository as IEventRepository,
} from '@nostr-relay/common'
import { Kysely, sql } from 'kysely'
import { isNil } from 'lodash'
import { TEventIdWithScore } from '../../types/event'
import { isGenericTagName, toGenericTag } from '../../utils'
import { EventSearchRepository } from './event-search.repository'
import { KyselyDb } from './kysely-db'
import { Database, EventRow } from './types'
import { buildEventRow, buildGenericTagRows, extractGenericTagsFrom } from './event-row-mapping'

@Injectable()
export class EventRepository extends IEventRepository {
  private readonly db: Kysely<Database>

  constructor(
    kyselyDb: KyselyDb,
    private readonly eventSearchRepository: EventSearchRepository,
  ) {
    super()
    this.db = kyselyDb.getDb()
  }

  isSearchSupported(): boolean {
    return true
  }

  async upsert(event: any) {
    const row = buildEventRow(event)
    const author = row.author
    const genericTags = row.generic_tags
    const expiredAt = row.expired_at
    const dTagValue = row.d_tag_value
    try {
      const { numInsertedOrUpdatedRows } = await this.db
        .transaction()
        .execute(async (trx) => {
          const eventInsertResult = await trx
            .insertInto('events')
            .values({
              ...row,
              create_date: 'NOW()',
            })
            .onConflict((oc) =>
              oc
                .columns(['author', 'kind', 'd_tag_value'])
                .where('d_tag_value', 'is not', null)
                .doUpdateSet({
                  id: (eb) => eb.ref('excluded.id'),
                  pubkey: (eb) => eb.ref('excluded.pubkey'),
                  author: (eb) => eb.ref('excluded.author'),
                  created_at: (eb) => eb.ref('excluded.created_at'),
                  tags: (eb) => eb.ref('excluded.tags'),
                  content: (eb) => eb.ref('excluded.content'),
                  sig: (eb) => eb.ref('excluded.sig'),
                  expired_at: (eb) => eb.ref('excluded.expired_at'),
                  generic_tags: (eb) => eb.ref('excluded.generic_tags'),
                  kid: (eb) => eb.ref('excluded.kid'),
                  key: (eb) => eb.ref('excluded.key'),
                  create_date: (eb) => eb.ref('excluded.create_date'),
                })
                .where((eb) =>
                  eb.or([
                    eb('events.created_at', '<', (eb) =>
                      eb.ref('excluded.created_at'),
                    ),
                    eb.and([
                      eb('events.created_at', '=', (eb) =>
                        eb.ref('excluded.created_at'),
                      ),
                      eb('events.id', '>', (eb) => eb.ref('excluded.id')),
                    ]),
                  ]),
                ),
            )
            .executeTakeFirst()

          if (eventInsertResult.numInsertedOrUpdatedRows === BigInt(0)) {
            return eventInsertResult
          }

          if (genericTags.length > 0) {
            await trx
              .deleteFrom('generic_tags')
              .where('event_id', '=', event.id)
              .execute()

            await trx
              .insertInto('generic_tags')
              .values(buildGenericTagRows(event, genericTags))
              .executeTakeFirst()
          }

          return eventInsertResult
        })

      if (numInsertedOrUpdatedRows === BigInt(0)) {
        return { success: true, isDuplicate: true }
      }

      // replaceable event
      if (dTagValue !== null) {
        await this.eventSearchRepository.deleteReplaceableEvents(
          author,
          event.kind,
          dTagValue,
        )
      }

      await this.eventSearchRepository.add(event, {
        author,
        genericTags,
        expiredAt,
        dTagValue,
      })

      return { success: true, isDuplicate: false }
    } catch (error: any) {
      if (error.code === '23505') {
        // 23505 is unique_violation
        return { success: true, isDuplicate: true }
      }
      throw error
    }
  }

  async find(filter: Filter): Promise<Event[]> {
    const limit = this.getLimitFrom(filter)
    if (limit === 0) return []

    if (filter.search) {
      return this.eventSearchRepository.find(filter)
    }

    const mapRowToEvent = (row: any): Event => {
      const ev: any = {
        id: row.id,
        pubkey: row.pubkey,
        uid: row.pubkey,
        kind: row.kind,
        tags: typeof row.tags === 'string' ? JSON.parse(row.tags) : row.tags,
        content: row.content,
        sig: row.sig,
        created_at: Number(row.created_at),
      }
      if (row.kid) {
        ev.kid = row.kid
      }
      if (row.key) {
        ev.key = row.key
      }
      return ev as Event
    }

    const genericTagsCollection = this.extractGenericTagsCollectionFrom(filter)
    if (!filter.ids?.length && genericTagsCollection.length) {
      // too complex query
      if (genericTagsCollection.length > 2) {
        return []
      }

      const rows = await this.createGenericTagsSelectQuery(
        filter,
        genericTagsCollection[0],
        genericTagsCollection[1],
      )
        .select([
          'e.id',
          'e.pubkey',
          'e.kind',
          'e.tags',
          'e.content',
          'e.sig',
          'e.created_at',
          'e.kid',
          'e.key',
        ])
        .limit(limit)
        .execute()

      return rows.map(mapRowToEvent)
    }

    const rows = await this.createSelectQuery(filter)
      .select(['id', 'pubkey', 'kind', 'tags', 'content', 'sig', 'created_at', 'kid', 'key'])
      .limit(limit)
      .execute()

    return rows.map(mapRowToEvent)
  }

  async findTopIds(filter: Filter): Promise<TEventIdWithScore[]> {
    const limit = this.getLimitFrom(filter, 1000)
    if (limit === 0) return []

    if (filter.search) {
      return this.eventSearchRepository.findTopIds(filter)
    }

    let partialEvents: Pick<EventRow, 'id' | 'created_at'>[] = []

    const genericTagsCollection = this.extractGenericTagsCollectionFrom(filter)
    if (!filter.ids?.length && genericTagsCollection.length) {
      // too complex query
      if (genericTagsCollection.length > 2) {
        return []
      }

      partialEvents = await this.createGenericTagsSelectQuery(
        filter,
        genericTagsCollection[0],
        genericTagsCollection[1],
      )
        .select(['e.id', 'e.created_at'])
        .limit(limit)
        .execute()
    } else {
      partialEvents = await this.createSelectQuery(filter)
        .select(['id', 'created_at'])
        .limit(limit)
        .execute()
    }

    // TODO: algorithm to calculate score
    return partialEvents.map((event) => ({
      id: event.id,
      score: event.created_at,
    }))
  }

  async deleteExpiredEvents() {
    const result = await this.db
      .deleteFrom('events')
      .where('expired_at', '<', getTimestampInSeconds())
      .executeTakeFirst()
    return parseInt(result.numDeletedRows.toString())
  }

  async destroy() {
    await this.db.destroy()
  }

  private createSelectQuery(filter: Filter) {
    let query = this.db.selectFrom('events')

    if (filter.ids?.length) {
      query = query.where('id', 'in', filter.ids)
    }

    if (filter.since) {
      query = query.where('created_at', '>=', filter.since)
    }

    if (filter.until) {
      query = query.where('created_at', '<=', filter.until)
    }

    if (filter.authors?.length) {
      query = query.where('author', 'in', filter.authors)
    }

    if (filter.kinds?.length) {
      query = query.where('kind', 'in', filter.kinds)
    }

    const genericTagsCollection = this.extractGenericTagsCollectionFrom(filter)
    if (genericTagsCollection.length) {
      genericTagsCollection.forEach((genericTags) => {
        query = query.where(
          'generic_tags',
          '&&',
          sql<string[]>`ARRAY[${sql.join(genericTags)}]`,
        )
      })
    }

    return query.orderBy('created_at desc')
  }

  private createGenericTagsSelectQuery(
    filter: Filter,
    firstGenericTagsFilter: string[],
    secondGenericTagsFilter?: string[],
  ) {
    let query = this.db
      .selectFrom('generic_tags as g')
      .distinctOn(['g.event_id', 'g.created_at'])
      .rightJoin('events as e', 'e.id', 'g.event_id')

    if (secondGenericTagsFilter?.length) {
      query = query.innerJoin('generic_tags as g2', (join) =>
        join
          .onRef('g2.event_id', '=', 'g.event_id')
          .on('g2.tag', 'in', secondGenericTagsFilter),
      )
    }

    query = query.where('g.tag', 'in', firstGenericTagsFilter)

    if (filter.since) {
      query = query.where('g.created_at', '>=', filter.since)
    }

    if (filter.until) {
      query = query.where('g.created_at', '<=', filter.until)
    }

    if (filter.authors?.length) {
      query = query.where('g.author', 'in', filter.authors)
    }

    if (filter.kinds?.length) {
      query = query.where('g.kind', 'in', filter.kinds)
    }

    return query.orderBy('g.created_at desc')
  }

  private getLimitFrom(filter: Filter, defaultLimit = 100) {
    return Math.min(isNil(filter.limit) ? defaultLimit : filter.limit, 1000)
  }

  private extractGenericTagsCollectionFrom(filter: Filter): string[][] {
    return Object.keys(filter)
      .filter((key) => key.startsWith('#') && filter[key].length > 0)
      .map((key) => {
        const tagName = key[1]
        return filter[key].map((v: string) => toGenericTag(tagName, v))
      })
      .sort((a, b) => a.length - b.length)
  }

  private extractGenericTagsFrom(event: Event): string[] {
    return extractGenericTagsFrom(event)
  }
}
