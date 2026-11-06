import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import { createServer } from "node:http";

const server = createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("wisp-js server");
});
// default log level (INFO), as a normal deployment runs it; DEBUG was a WispMark leftover (changed 2026-10-22)
wisp.options.allow_private_ips = true;
wisp.options.allow_loopback_ips = true;

server.on("upgrade", (req, socket, head) => {
  wisp.routeRequest(req, socket, head);
});

server.on("listening", () => {
  console.log("HTTP server listening");
});

server.listen(process.argv[2], "127.0.0.1");