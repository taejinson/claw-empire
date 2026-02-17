import { useEffect, useRef, useCallback, useState } from "react";
import type { WSEvent, WSEventType } from "../types";

type Listener = (payload: unknown) => void;

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const listenersRef = useRef<Map<WSEventType, Set<Listener>>>(new Map());
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${location.host}/ws`;
    let alive = true;
    let ws: WebSocket;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    function connect() {
      if (!alive) return;
      ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (alive) setConnected(true);
      };
      ws.onclose = () => {
        if (!alive) return;
        setConnected(false);
        reconnectTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        if (!alive) return;
        try {
          const evt: WSEvent = JSON.parse(e.data);
          const listeners = listenersRef.current.get(evt.type);
          if (listeners) {
            for (const fn of listeners) fn(evt.payload);
          }
        } catch {}
      };
    }

    connect();
    return () => {
      alive = false;
      clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, []);

  const on = useCallback((type: WSEventType, fn: Listener) => {
    if (!listenersRef.current.has(type)) {
      listenersRef.current.set(type, new Set());
    }
    listenersRef.current.get(type)!.add(fn);
    return () => { listenersRef.current.get(type)?.delete(fn); };
  }, []);

  return { connected, on };
}
