import { serve, type ServerWebSocket, CryptoHasher } from "bun";
import index from "./index.html";
import v8 from "node:v8";
import * as Pusher from "pusher";

const ADAPTER = process.env.BUNPUSH_ADAPTER || "local";
const ACCEPT_TRAFFIC_MEMORY_THRESHOLD = Number(
  process.env.BUNPUSH_ACCEPT_TRAFFIC_MEMORY_THRESHOLD || 75
);

const privateChannelPatterns = [
  "private-*",
  "private-encrypted-*",
  "presence-*",
];

const cachingChannelPatterns = [
  "cache-*",
  "private-cache-*",
  "private-encrypted-cache-*",
  "presence-cache-*",
];

interface PresenceMemberInfo {
  [key: string]: any;
}

type PresenceMember = {
  user_id: number | string;
  user_info: PresenceMemberInfo;
  socket_id?: string;
};

type WebhookEventType =
  | "client_event"
  | "channel_occupied"
  | "channel_vacated"
  | "member_added"
  | "member_removed";

type WebhookInterface = {
  url?: string;
  headers?: {
    [key: string]: string;
  };
  lambda_function?: string;
  event_types: WebhookEventType[];
  filter?: {
    channel_name_starts_with?: string;
    channel_name_ends_with?: string;
  };
  lambda: {
    async?: boolean;
    region?: string;
  };
};

type AppInterface = {
  id: string | number;
  key: string;
  secret: string;
  maxConnections: string | number;
  enableClientMessages: boolean;
  enabled: boolean;
  maxBackendEventsPerSecond?: number;
  maxClientEventsPerSecond: number;
  maxReadRequestsPerSecond?: number;
  webhooks?: WebhookInterface[];
  maxPresenceMembersPerChannel?: number;
  maxPresenceMemberSizeInKb?: number;
  maxChannelNameLength?: number;
  maxEventChannelsAtOnce?: number;
  maxEventNameLength?: number;
  maxEventPayloadInKb?: number;
  maxEventBatchSize?: number;
  enableUserAuthentication?: boolean;
  hasClientEventWebhooks?: boolean;
  hasChannelOccupiedWebhooks?: boolean;
  hasChannelVacatedWebhooks?: boolean;
  hasMemberAddedWebhooks?: boolean;
  hasMemberRemovedWebhooks?: boolean;
};

interface MessageData {
  channel_data?: string;
  channel?: string;
  user_data?: string;
  [key: string]: any;
}

interface PusherMessage {
  channel?: string;
  name?: string;
  event?: string;
  data?: MessageData;
}

interface PusherApiMessage {
  name?: string;
  data?: string | { [key: string]: any };
  channel?: string;
  channels?: string[];
  socket_id?: string;
}

interface SentPusherMessage {
  channel?: string;
  event?: string;
  data?: MessageData | string;
}

const apps: AppInterface[] = [
  {
    id: process.env.BUNPUSH_APP_ID ?? "111",
    key: process.env.BUNPUSH_APP_KEY ?? "222",
    secret: process.env.BUNPUSH_APP_SECRET ?? "333",
    maxClientEventsPerSecond: 100,
    enabled: true,
    webhooks: [],
    enableClientMessages: true,
    maxConnections: 100,
  },
];

type WebsocketData = {
  id: string;
  protocol?: number;
  client?: string | null;
  version?: string | null;
  flash?: boolean;
  key: string;
};

type Namespace = {
  appId: string;
  connections: Map<
    string,
    {
      ws: ServerWebSocket<WebsocketData>;
      presence: Map<string, PresenceMember>;
    }
  >;
  channels: Map<string, Set<string>>;
};

const namespaces: Map<string, Namespace> = new Map<string, Namespace>();

function generateSocketId(): string {
  const min = 0;
  const max = 10000000000;
  return randomNumber(min, max) + "." + randomNumber(min, max);
}

function randomNumber(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}

type SigningTokenInitialParams = {
  auth_key: string;
  auth_timestamp?: string | number | null;
  auth_version?: string | null;
  auth_signature: string | null;
  body_md5: string;
  appId: string;
  appKey: string;
  channelName: string;
};

async function getSigningToken({
  initialParams,
  rawBody,
  paramBodyMd5,
  method,
  url,
  app,
}: {
  initialParams: SigningTokenInitialParams;
  rawBody?: string;
  paramBodyMd5?: string | null;
  method: string;
  url: string;
  app: AppInterface;
}) {
  const {
    auth_signature,
    body_md5,
    appId,
    appKey,
    channelName,
    ...otherParams
  } = initialParams;

  let params: typeof otherParams & { body_md5?: string } = otherParams;
  if (rawBody || paramBodyMd5) {
    params = {
      ...params,
      body_md5: new CryptoHasher("md5")
        .update(rawBody ?? paramBodyMd5 ?? "", "utf8")
        .digest("hex"),
    };
  }
  const queryParams = Object.entries(params)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");

  return signToken([method, url, queryParams].join("\n"), app.secret);
}

function signToken(data: string, secret: string) {
  return new CryptoHasher("sha256", secret)
    .update(Buffer.from(data))
    .digest("hex");
}

function checkSignature({
  signature,
  app,
  ws,
  channel,
  channelData,
}: {
  signature: string;
  app: AppInterface;
  ws: ServerWebSocket<WebsocketData>;
  channel: string;
  channelData?: string;
}) {
  return (
    signature ===
    `${app.key}:${signToken(
      `${ws.data.id}:${channel}` + (channelData ? `:${channelData}` : ""),
      app.secret
    )}`
  );
}

async function getApp({ id, key }: { id?: string | number; key?: string }) {
  if (ADAPTER === "pgsql") {
    const [app] = await Bun.sql<AppInterface[]>`select * from apps
    where (${id} is not null and id = ${id})
    or (${key} is not null and key = ${key})
    limit 1`;
    return app;
  }
  return apps.find(
    (app) => app.id.toString() === id?.toString() || app.key === key
  );
}

function getNamespace(app: AppInterface) {
  if (!namespaces.has(app.id.toString())) {
    namespaces.set(app.id.toString(), {
      appId: app.id.toString(),
      connections: new Map(),
      channels: new Map(),
    });
  }
  return namespaces.get(app.id.toString())!;
}

function addConnection(app: AppInterface, ws: ServerWebSocket<WebsocketData>) {
  const namespace = getNamespace(app);
  namespace.connections.set(ws.data.id, { ws, presence: new Map() });
}

function getChannel(app: AppInterface, channelName: string) {
  const namespace = getNamespace(app);
  if (!namespace.channels.has(channelName)) {
    namespace.channels.set(channelName, new Set());
  }
  return namespace.channels.get(channelName)!;
}

function subscribeChannel(
  app: AppInterface,
  channelName: string,
  ws: ServerWebSocket<WebsocketData>
) {
  getChannel(app, channelName).add(ws.data.id);
}

function unsubscribeChannel(
  app: AppInterface,
  channelName: string,
  ws: ServerWebSocket<WebsocketData>
) {
  getChannel(app, channelName).delete(ws.data.id);
}

function getConnectionsForChannel(app: AppInterface, channelName: string) {
  const namespace = namespaces.get(app.id.toString());
  return (
    namespace?.channels
      .get(channelName)
      ?.values()
      .map((id) => namespace?.connections.get(id))
      .filter((ws) => ws !== undefined) ?? []
  );
}

function getChannelType(
  name: string
): "presence" | "private-encrypted" | "private" | "public" {
  if (name.lastIndexOf("presence-", 0) === 0) {
    return "presence";
  }
  if (name.lastIndexOf("private-encrypted-", 0) === 0) {
    return "private-encrypted";
  }
  if (
    privateChannelPatterns.some((pattern) =>
      new RegExp(pattern.replace("*", ".*")).test(name)
    )
  ) {
    return "private";
  }
  return "public";
}

function restrictedChannelName(name: string) {
  return /^#?[-a-zA-Z0-9_=@,.;]+$/.test(name) === false;
}

function dataToBytes(...data: any) {
  return data?.reduce((totalBytes: number, element: string | {}) => {
    const elem =
      typeof element === "string" ? element : JSON.stringify(element);

    try {
      return (totalBytes += Buffer.byteLength(elem, "utf8"));
    } catch (e) {
      return totalBytes;
    }
  }, 0);
}

const server = serve({
  websocket: {
    backpressureLimit: 1024 * 1024,
    maxPayloadLength: 100 * 1024 * 1024, // 100MB

    async open(ws) {
      const subscribedChannels = new Set();
      const presence = new Map();
      const app = await getApp({ key: ws.data.key });
      if (!app) {
        ws.send(
          JSON.stringify({
            event: "pusher:error",
            data: JSON.stringify({
              code: 4001,
              message: `App key ${ws.data.key} does not exist.`,
            }),
          })
        );
        ws.close(4001, "App key does not exist.");
        return;
      }
      if (!app.enabled) {
        ws.send(
          JSON.stringify({
            event: "pusher:error",
            data: JSON.stringify({
              code: 4003,
              message: `App is disabled.`,
            }),
          })
        );
        ws.close(4003, "App is disabled.");
        return;
      }

      addConnection(app, ws);
      ws.send(
        JSON.stringify({
          event: "pusher:connection_established",
          data: {
            socket_id: ws.data.id!,
            activity_timeout: 30,
          },
        })
      );
    },
    async message(ws, message) {
      const messageData = JSON.parse(message.toString()) as PusherMessage;
      const app = await getApp({ key: ws.data.key });
      if (!app) {
        ws.send(
          JSON.stringify({
            event: "pusher:error",
            data: JSON.stringify({
              code: 4001,
              message: `App key ${ws.data.key} does not exist.`,
            }),
          })
        );
        ws.close(4001, "App key does not exist.");
        return;
      }
      const namespace = getNamespace(app);
      if (messageData.event === "pusher:ping") {
        ws.send(
          JSON.stringify({
            event: "pusher:pong",
            data: {},
          })
        );
      } else if (messageData.event === "pusher:subscribe") {
        const channelName = messageData.data?.channel;
        if (!channelName) {
          ws.send(
            JSON.stringify({
              event: "pusher:error",
              data: JSON.stringify({
                code: 4002,
                message: "Channel is required.",
              }),
            })
          );
          return;
        }

        if (restrictedChannelName(channelName)) {
          ws.send(
            JSON.stringify({
              event: "pusher:subscription_error",
              channel: channelName,
              data: JSON.stringify({
                code: 4009,
                message:
                  "The channel name is not allowed. Read channel conventions: https://pusher.com/docs/channels/using_channels/channels/#channel-naming-conventions",
              }),
            })
          );
          return;
        }

        const channelType = getChannelType(channelName);
        const channel = getChannel(app, channelName);
        if (channelType === "private" || channelType === "presence") {
          if (
            checkSignature({
              app,
              ws,
              channel: channelName,
              channelData:
                channelType === "presence"
                  ? messageData.data?.channel_data
                  : undefined,
              signature: messageData.data?.auth ?? "",
            })
          ) {
            ws.send(
              JSON.stringify({
                event: "pusher:subscription_error",
                channel: channelName,
                data: JSON.stringify({
                  code: 4002,
                  message: "Channel is required.",
                }),
              })
            );
            return;
          }
        }
        if (channelType !== "presence") {
          channel.add(ws.data.id);

          ws.send(
            JSON.stringify({
              event: "pusher_internal:subscription_succeeded",
              channel: channelName,
            })
          );
          return;
        }

        if (
          app.maxPresenceMembersPerChannel &&
          channel.size + 1 > app.maxPresenceMembersPerChannel
        ) {
          ws.send(
            JSON.stringify({
              event: "pusher:subscription_error",
              channel: channelName,
              data: JSON.stringify({
                code: 4100,
                message:
                  "The maximum members per presence channel limit was reached",
              }),
            })
          );
          return;
        }
        let member = JSON.parse(
          messageData.data?.channel_data ?? "{}"
        ) as PresenceMember;

        let memberSizeInKb = dataToBytes(member.user_info) / 1024;
        if (
          app.maxPresenceMemberSizeInKb &&
          memberSizeInKb > app.maxPresenceMemberSizeInKb
        ) {
          ws.send(
            JSON.stringify({
              event: "pusher:subscription_error",
              channel: channelName,
              data: JSON.stringify({
                code: 4301,
                message: `The maximum size for a channel member is ${app.maxPresenceMemberSizeInKb} KB.`,
              }),
            })
          );
          return;
        }
        namespace.connections
          .get(ws.data.id)
          ?.presence.set(channelName, member);

        const members = getConnectionsForChannel(app, channelName);
        if (
          undefined === members.find((conn) => conn.ws.data.id === ws.data.id)
        ) {
          await Promise.all(
            members.map(({ ws }) =>
              ws.send(
                JSON.stringify({
                  event: "pusher_internal:member_added",
                  channel: channelName,
                  data: JSON.stringify({
                    user_id: member.user_id,
                    user_info: member.user_info,
                  }),
                })
              )
            )
          );
          channel.add(ws.data.id);
          ws.send(
            JSON.stringify({
              event: "pusher_internal:subscription_succeeded",
              channel: channelName,
              data: JSON.stringify({
                presence: {
                  ids: channel.values().toArray(),
                  hash: Object.fromEntries(channel.entries()),
                  count: channel.size,
                },
              }),
            })
          );
        }
      } else if (messageData.event === "pusher:unsubscribe") {
        const channelName = messageData.data?.channel;
        if (!channelName) {
          ws.send(
            JSON.stringify({
              event: "pusher:error",
              data: {
                code: 4002,
                message: "Channel is required.",
              },
            })
          );
          return;
        }
        unsubscribeChannel(app, channelName, ws);
        const channelType = getChannelType(channelName);
        if (channelType === "presence") {
          const member = namespace.connections
            .get(ws.data.id)
            ?.presence.get(channelName);
          namespace.connections.get(ws.data.id)?.presence.delete(channelName);
          getConnectionsForChannel(app, channelName).map(({ ws }) =>
            ws.send(
              JSON.stringify({
                event: "pusher_internal:member_removed",
                channel: channelName,
                data: JSON.stringify({
                  user_id: member?.user_id,
                  user_info: member?.user_info,
                }),
              })
            )
          );
        }
        ws.send(
          JSON.stringify({
            event: "pusher_internal:unsubscribed",
            channel: channelName,
          })
        );
      } else if (new RegExp("^client-.*").test(messageData.event ?? "")) {
        let { event, data, channel } = messageData;
        if (!app.enableClientMessages) {
          ws.send(
            JSON.stringify({
              event: "pusher:error",
              channel,
              data: {
                code: 4301,
                message: `The app does not have client messaging enabled.`,
              },
            })
          );
          return;
        }
        // Make sure the event name length is not too big.
        if (
          app.maxEventNameLength &&
          (event?.length ?? 0) > app.maxEventNameLength
        ) {
          ws.send(
            JSON.stringify({
              event: "pusher:error",
              channel,
              data: {
                code: 4301,
                message: `Event name is too long. Maximum allowed size is ${app.maxEventNameLength}.`,
              },
            })
          );

          return;
        }
        const dataBytes = dataToBytes(data);
        const payloadSizeInKb = dataBytes / 1024;
        if (
          app.maxEventPayloadInKb &&
          payloadSizeInKb > app.maxEventPayloadInKb
        ) {
          ws.send(
            JSON.stringify({
              event: "pusher:error",
              channel,
              data: {
                code: 4301,
                message: `Payload size is too large. Maximum allowed size is ${app.maxEventPayloadInKb} KB.`,
              },
            })
          );

          return;
        }
      } else if (messageData.event === "pusher:signin") {
      } else {
        console.log("messageData event handler not implemented.", messageData);
      }
    },
    async close(ws, code, reason) {
      console.log("closed", { ws, code, reason });
    },
    async ping(ws, data) {
      ws.pong(JSON.stringify({ event: "pusher:pong", data: {} }));
      console.log("ping", ws, data);
    },
    async pong(ws, data) {
      console.log("pong", ws, data);
    },
    data: {} as WebsocketData,
  },
  routes: {
    "/": index,
    "/api/test-trigger": (req) => {
      const pusher = new Pusher.default({
        appId: process.env.BUNPUSH_APP_ID ?? "111",
        key: process.env.BUNPUSH_APP_KEY ?? "222",
        secret: process.env.BUNPUSH_APP_SECRET ?? "333",
        cluster: "ap1",
        host: "bunpush.com",
      });
      pusher.trigger("my-channel", "my-event", { message: "hello" });
      return new Response("OK");
    },
    "/app/:key": (req, server) => {
      const url = new URL(req.url);
      if (
        server.upgrade(req, {
          data: {
            protocol: Number(url.searchParams.get("protocol")),
            client: url.searchParams.get("client"),
            version: url.searchParams.get("version"),
            flash: url.searchParams.get("flash") === "true",
            key: req.params.key,
            id: generateSocketId(),
          },
        })
      ) {
        return; // do not return a Response
      }
      return new Response("Upgrade failed", { status: 500 });
    },
    "/apps/:id/events": {
      POST: async (req) => {
        const app = await getApp({ id: req.params.id });
        if (!app) {
          return new Response("App Not Found", { status: 404 });
        }
        const url = new URL(req.url);
        const rawBody = await req.body?.text();
        const paramBodyMd5 = url.searchParams.get("body_md5");
        const initialParams = {
          auth_key: app.key,
          auth_timestamp: Number(url.searchParams.get("auth_timestamp")),
          auth_version: url.searchParams.get("auth_version"),
          ...url.searchParams.toJSON(),
        } as SigningTokenInitialParams;
        const token = await getSigningToken({
          initialParams,
          rawBody,
          paramBodyMd5,
          method: req.method.toUpperCase(),
          url: url.pathname,
          app,
        });
        if (token !== url.searchParams.get("auth_signature")) {
          return Response.json({ error: "Invalid Signature" }, { status: 400 });
        }
        const data = JSON.parse(rawBody ?? "") as PusherApiMessage;

        for (const channelName of data.channels ?? []) {
          await Promise.all(
            getConnectionsForChannel(app, channelName)?.map(({ ws }) =>
              ws.send(
                JSON.stringify({
                  event: data.name,
                  data: data.data,
                  channel: channelName,
                })
              )
            )
          );
        }
        return Response.json({ ok: true });
      },
    },
    "/apps/:id/channels": async (req) => {
      const app = await getApp({ id: req.params.id });
      if (!app) {
        return new Response("Not Found", { status: 404 });
      }
      const url = new URL(req.url);
      const data = namespaces
        .get(app.id.toString())
        ?.channels.entries()
        .filter(([name]) =>
          url.searchParams.get("filter_by_prefix")
            ? name.startsWith(url.searchParams.get("filter_by_prefix") ?? "")
            : true
        )
        .map(([name, conns]) => ({
          name,
          subscription_count: conns.size,
          occupied: conns.size > 0,
        }))
        .toArray();

      return Response.json({ data });
    },
    "/apps/:id/channels/:name": async (req) => {
      const app = await getApp({ id: req.params.id });
      if (!app) {
        return new Response("Not Found", { status: 404 });
      }
      const channel = namespaces
        .get(app.id.toString())
        ?.channels.get(req.params.name);
      if (!channel) {
        return new Response("Not Found", { status: 404 });
      }
      const data = {
        name: req.params.name,
        subscription_count: channel.size,
        occupied: channel.size > 0,
      };
      return Response.json({ data });
    },
    "/accept-traffics": () => {
      const treshold = ACCEPT_TRAFFIC_MEMORY_THRESHOLD;
      let { rss, heapTotal, external, arrayBuffers } = process.memoryUsage();

      let totalSize = v8.getHeapStatistics().total_available_size;
      let usedSize = rss + heapTotal + external + arrayBuffers;
      let percentUsage = (usedSize / totalSize) * 100;
      if (percentUsage > treshold) {
        return new Response("Memory usage is too high", { status: 500 });
      }
      return Response.json({
        memory: { usedSize, totalSize, percentUsage },
      });
    },
    "/up": () => new Response("OK"),
    "/ready": () => new Response("OK"),
  },
  fetch(req) {
    return new Response("Not Found", {
      status: 404,
    });
  },
  error(error) {
    console.error(
      `Uncaught server error: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
    return new Response("Internal Server Error", { status: 500 });
  },
});

console.log(`Listening on ${server.url}`);
