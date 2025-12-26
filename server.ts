import { serve, randomUUIDv7, env, CryptoHasher } from "bun";
import home from "home.html";
const APP_KEY = env.APP_KEY || randomUUIDv7();
console.log("starting server with bun version", Bun.version);
const server = serve({
  routes: {
    "/": home,
    "/up": () => new Response("OK"),
    "/test": async () => {
      await fetch("http://localhost:3000/channels/my-channel/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-App-Key": new CryptoHasher("sha256", APP_KEY)
            .update(
              ["POST", "http://localhost:3000/channels/my-channel/events"].join(
                "\n"
              )
            )
            .digest("hex"),
        },
        body: JSON.stringify({
          hello: "bunpush",
        }),
      }).catch((e) => console.error(e));
      return new Response("OK");
    },
    "/channels/:channel/subscribe": (req, server) => {
      const success = server.upgrade(req, {
        data: {
          id: randomUUIDv7(),
          channel: req.params.channel,
        },
      });
      if (!success) return new Response("Upgrade failed", { status: 400 });
    },
    "/channels/:channel/events": {
      POST: async (req, server) => {
        if (
          req.headers.get("x-app-key") !==
          new CryptoHasher("sha256", APP_KEY)
            .update([req.method, req.url].join("\n"))
            .digest("hex")
        ) {
          return new Response("Unauthorized", { status: 401 });
        }
        server.publish(req.params.channel, await req.arrayBuffer());
        return new Response("OK", {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
          },
        });
      },
      OPTIONS: () => {
        return new Response("", {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
          },
        });
      },
    },
  },
  websocket: {
    data: {} as { id: string; channel: string },
    async open(ws) {
      ws.subscribe(ws.data.channel);
      ws.send("OK");
    },
    async message(ws, message) {
      if (message === "ping") {
        ws.send("pong");
      }
    },
    async drain(ws) {
      console.log("drain");
    },
    async close(ws, code, reason) {
      ws.unsubscribe(ws.data.channel);
    },
  },
});

console.log(`Server started on ${server.url}`);
