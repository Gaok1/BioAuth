'use strict';

// The only bridge between the renderer and the main process.
//
// Everything exposed here is reachable by any script that runs in the window,
// so the surface is kept to: ask the agent something, listen for pushes. There
// is no way from here to reach the socket, the token, the filesystem or Node.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('phoneAuth', {
  /** Calls an allow-listed agent method. */
  call: (method, params) => ipcRenderer.invoke('agent:call', method, params),

  /** Connection state, for the offline banner. */
  info: () => ipcRenderer.invoke('agent:info'),

  /** Renders a pairing code as a data URI. */
  renderQr: (text) => ipcRenderer.invoke('qr:render', text),

  /** Subscribes to connection changes. Returns an unsubscribe function. */
  onStatus: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('agent:status', listener);
    return () => ipcRenderer.removeListener('agent:status', listener);
  },

  /** Subscribes to agent event pushes. Returns an unsubscribe function. */
  onEvent: (handler) => {
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on('agent:event', listener);
    return () => ipcRenderer.removeListener('agent:event', listener);
  },
});
