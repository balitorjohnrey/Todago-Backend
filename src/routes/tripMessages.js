const OPEN_STATUSES = ['accepted', 'pickup', 'ongoing', 'arrived'];
const INBOX_PAGE_SIZE = 30;
const THREAD_PAGE_SIZE = 40;
const CAN_SEND = `COALESCE(tr.driver_id IS NOT NULL AND tr.commuter_id IS NOT NULL
  AND tr.status = ANY($2::text[]), false)`;

function requireTripParticipantRole(req, res, next) {
  const driver = req.userRole === 'driver';
  if (!driver && !['passenger', 'commuter'].includes(req.userRole)) {
    return res.status(403).json({ success: false, message: 'Trip participant access only' });
  }
  req.tripChat = {
    ownerColumn: driver ? 'driver_id' : 'commuter_id',
    peerJoin: driver
      ? 'LEFT JOIN users peer ON peer.id = tr.commuter_id'
      : 'LEFT JOIN drivers peer ON peer.driver_id = tr.driver_id',
    peerName: driver
      ? "COALESCE(peer.full_name, 'Passenger')"
      : "COALESCE(peer.driver_name, 'Driver')",
    senderRole: driver ? 'driver' : 'passenger',
  };
  next();
}

function registerTripMessages(router, requireAuth, { dbGet, dbAll }) {
  router.get('/conversations', requireAuth, requireTripParticipantRole, async (req, res) => {
    const { before, beforeTripId } = req.query;
    if ((before !== undefined || beforeTripId !== undefined)
        && (typeof before !== 'string' || !/^-?\d{1,16}$/.test(before)
          || typeof beforeTripId !== 'string' || !beforeTripId || beforeTripId.includes('\0'))) {
      return res.status(422).json({ success: false, message: 'Invalid conversation cursor' });
    }

    try {
      const { ownerColumn, peerJoin, peerName } = req.tripChat;
      const rows = await dbAll(`
        WITH conversations AS (
          SELECT tr.trip_id, tr.destination, ${peerName} AS peer_name,
            ${CAN_SEND} AS can_send, latest.body AS last_message,
            COALESCE(latest.created_at, tr.request_timestamp, TIMESTAMPTZ 'epoch') AS activity_at
          FROM trips tr
          ${peerJoin}
          LEFT JOIN LATERAL (
            SELECT m.body, m.created_at FROM trip_messages m
            WHERE m.trip_id = tr.trip_id ORDER BY m.message_id DESC LIMIT 1
          ) latest ON true
          WHERE tr.${ownerColumn} = $1 AND (latest.body IS NOT NULL OR ${CAN_SEND})
        ), dated AS (
          SELECT *, FLOOR(EXTRACT(EPOCH FROM activity_at) * 1000)::bigint AS activity_ms
          FROM conversations
        )
        SELECT * FROM dated
        WHERE $3::bigint IS NULL OR (activity_ms, trip_id) < ($3, $4::text)
        ORDER BY activity_ms DESC, trip_id DESC LIMIT $5`,
      [req.userId, OPEN_STATUSES, before ?? null, beforeTripId ?? null, INBOX_PAGE_SIZE + 1]);
      const conversations = rows.slice(0, INBOX_PAGE_SIZE);
      const last = conversations.at(-1);
      return res.json({
        success: true,
        conversations: conversations.map(({ activity_ms, ...row }) => row),
        nextCursor: rows.length > INBOX_PAGE_SIZE
          ? { before: String(last.activity_ms), beforeTripId: last.trip_id }
          : null,
      });
    } catch (error) {
      console.error('[Trip messages] Inbox error:', error.message);
      return res.status(500).json({ success: false, message: 'Could not load conversations' });
    }
  });

  router.get('/:tripId/messages', requireAuth, requireTripParticipantRole, async (req, res) => {
    const { before } = req.query;
    if (before !== undefined && (typeof before !== 'string' || !/^[1-9]\d{0,18}$/.test(before)
        || BigInt(before) > 9223372036854775807n)) {
      return res.status(422).json({ success: false, message: 'Invalid message cursor' });
    }

    try {
      const { ownerColumn, peerJoin, peerName } = req.tripChat;
      const row = await dbGet(`
        SELECT tr.trip_id, tr.pickup_location, tr.destination, ${peerName} AS peer_name,
          ${CAN_SEND} AS can_send, COALESCE(page.messages, '[]'::json) AS messages
        FROM trips tr
        ${peerJoin}
        LEFT JOIN LATERAL (
          SELECT json_agg(json_build_object('message_id', m.message_id::text,
            'sender_role', m.sender_role, 'body', m.body, 'created_at', m.created_at)
            ORDER BY m.message_id DESC) AS messages
          FROM (
            SELECT message_id, sender_role, body, created_at FROM trip_messages
            WHERE trip_id = tr.trip_id AND ($4::bigint IS NULL OR message_id < $4)
            ORDER BY message_id DESC LIMIT $5
          ) m
        ) page ON true
        WHERE tr.${ownerColumn} = $1 AND tr.trip_id = $3`,
      [req.userId, OPEN_STATUSES, req.params.tripId, before ?? null, THREAD_PAGE_SIZE + 1]);
      if (!row) return res.status(404).json({ success: false, message: 'Conversation not found' });

      const { messages, ...conversation } = row;
      const page = messages.slice(0, THREAD_PAGE_SIZE);
      return res.json({
        success: true, conversation, messages: page,
        nextCursor: messages.length > THREAD_PAGE_SIZE ? page.at(-1).message_id : null,
      });
    } catch (error) {
      console.error('[Trip messages] Conversation error:', error.message);
      return res.status(500).json({ success: false, message: 'Could not load the conversation' });
    }
  });

  router.post('/:tripId/messages', requireAuth, requireTripParticipantRole, async (req, res) => {
    const { message, requestId } = req.body || {};
    const text = typeof message === 'string' ? message.trim() : '';
    if (!text || text.includes('\0') || Array.from(text).length > 500) {
      return res.status(422).json({ success: false, message: 'Enter a message of 1–500 characters.' });
    }
    if (typeof requestId !== 'string' || !/^[a-f0-9]{32}$/.test(requestId)) {
      return res.status(422).json({ success: false, message: 'Invalid message request ID' });
    }

    try {
      const { ownerColumn, senderRole } = req.tripChat;
      const { tripId } = req.params;
      // Lock the trip until insertion completes so closing the trip and sending
      // a message have a definite order, including concurrent requests.
      const inserted = await dbGet(`
        WITH open_trip AS (
          SELECT tr.trip_id FROM trips tr
          WHERE tr.${ownerColumn} = $1 AND tr.trip_id = $3 AND ${CAN_SEND}
          FOR NO KEY UPDATE
        )
        INSERT INTO trip_messages (trip_id, sender_role, request_id, body)
        SELECT trip_id, $4, $5, $6 FROM open_trip
        ON CONFLICT (trip_id, sender_role, request_id) DO NOTHING
        RETURNING message_id::text`,
      [req.userId, OPEN_STATUSES, tripId, senderRole, requestId, text]);
      if (inserted) return res.status(201).json({ success: true });

      // A retry can acknowledge a committed message even if the trip has closed.
      const prior = await dbGet(`
        SELECT m.body FROM trips tr
        LEFT JOIN trip_messages m ON m.trip_id = tr.trip_id
          AND m.sender_role = $3 AND m.request_id = $4
        WHERE tr.${ownerColumn} = $1 AND tr.trip_id = $2`,
      [req.userId, tripId, senderRole, requestId]);
      if (!prior) return res.status(404).json({ success: false, message: 'Conversation not found' });
      if (prior.body === text) return res.json({ success: true });
      return res.status(409).json({
        success: false,
        message: prior.body ? 'That message ID has already been used.' : 'This conversation is closed for new messages.',
      });
    } catch (error) {
      console.error('[Trip messages] Send error:', error.code || 'unknown');
      return res.status(500).json({ success: false, message: 'Could not send the message. Try again.' });
    }
  });
}

module.exports = { registerTripMessages };
