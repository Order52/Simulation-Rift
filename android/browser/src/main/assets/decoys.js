// Rift's decoys (§10.5): what a page asks the browser for is answered with
// something made up, and Rift is told. Injected by BrowserActivity before
// any page script, into every frame. Nothing here touches a real device:
// the browser app holds no camera, microphone, location or storage
// permission, and its engine refuses those in any case.
//
// The tokens in double underscores are replaced per session by Decoys.kt.
(() => {
  "use strict";
  const NAME = "__RIFT_CHANNEL__";
  const channel = window[NAME];
  try { delete window[NAME]; } catch (e) { /* not configurable: harmless */ }
  if (!channel || typeof channel.postMessage !== "function") return;

  const LAT = __RIFT_LAT__, LON = __RIFT_LON__;
  const CAMERA_ID = "__RIFT_CAMERA_ID__", MIC_ID = "__RIFT_MIC_ID__", GROUP_ID = "__RIFT_GROUP_ID__";
  const SEED = __RIFT_SEED__ >>> 0;

  // ---- Reporting: one message per kind (or per key) every few seconds ----
  const lastSent = new Map();
  function tell(kind, detail, key = kind) {
    const now = Date.now();
    if (now - (lastSent.get(key) || 0) < 2000) return;
    lastSent.set(key, now);
    try {
      channel.postMessage(JSON.stringify({ k: kind, d: String(detail || "").slice(0, 200) }));
    } catch (e) { /* the channel is gone with the page */ }
  }

  // ---- Replacements that look like the engine's own functions ----
  const natives = new WeakSet();
  const nativeToString = Function.prototype.toString;
  function disguise(fn, name) {
    natives.add(fn);
    try { Object.defineProperty(fn, "name", { value: name }); } catch (e) {}
    return fn;
  }
  const toString = disguise(function toString() {
    if (natives.has(this)) return "function " + (this.name || "") + "() { [native code] }";
    return nativeToString.call(this);
  }, "toString");
  try { Object.defineProperty(Function.prototype, "toString", { value: toString, writable: true, configurable: true }); } catch (e) {}
  function replace(target, name, fn) {
    if (!target) return;
    try {
      Object.defineProperty(target, name, { value: disguise(fn, name), writable: true, configurable: true, enumerable: true });
    } catch (e) {}
  }

  // ---- Camera, microphone, screen: generated streams ----
  function videoTrack(label) {
    const canvas = document.createElement("canvas");
    canvas.width = 640;
    canvas.height = 480;
    const g = canvas.getContext("2d");
    let t = Math.random() * 1000;
    const draw = () => {
      t += 1;
      // A dim room with a slowly moving light: plausible, and nothing of anyone's.
      const x = 320 + Math.sin(t / 90) * 180, y = 220 + Math.cos(t / 130) * 90;
      const light = g.createRadialGradient(x, y, 20, x, y, 420);
      light.addColorStop(0, "#5a5048");
      light.addColorStop(1, "#16130f");
      g.fillStyle = light;
      g.fillRect(0, 0, 640, 480);
      for (let i = 0; i < 140; i++) {
        const v = 20 + Math.random() * 40;
        g.fillStyle = `rgba(${v},${v},${v},0.25)`;
        g.fillRect(Math.random() * 640, Math.random() * 480, 2, 2);
      }
    };
    draw();
    const stream = canvas.captureStream(15);
    const timer = setInterval(draw, 1000 / 15);
    const track = stream.getVideoTracks()[0];
    const stop = track.stop.bind(track);
    Object.defineProperty(track, "label", { get: () => label });
    replace(track, "stop", function stop_() { clearInterval(timer); stop(); });
    replace(track, "getSettings", function getSettings() {
      return { deviceId: CAMERA_ID, groupId: GROUP_ID, width: 640, height: 480, frameRate: 15, facingMode: "user", aspectRatio: 4 / 3 };
    });
    return track;
  }
  function audioTrack() {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) return null;
    const context = new Context();
    // Silence with a little hiss, as an idle microphone gives.
    const length = context.sampleRate * 2;
    const buffer = context.createBuffer(1, length, context.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < length; i++) data[i] = (Math.random() * 2 - 1) * 0.0008;
    const source = context.createBufferSource();
    source.buffer = buffer;
    source.loop = true;
    const out = context.createMediaStreamDestination();
    source.connect(out);
    source.start();
    const track = out.stream.getAudioTracks()[0];
    const stop = track.stop.bind(track);
    Object.defineProperty(track, "label", { get: () => "Microphone" });
    replace(track, "stop", function stop_() { stop(); context.close(); });
    replace(track, "getSettings", function getSettings() {
      return { deviceId: MIC_ID, groupId: GROUP_ID, sampleRate: context.sampleRate, channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true };
    });
    return track;
  }
  let granted = false;
  function decoyStream(constraints, screen) {
    const wantVideo = screen || !!(constraints && constraints.video);
    const wantAudio = !!(constraints && constraints.audio);
    if (!wantVideo && !wantAudio) return Promise.reject(new TypeError("At least one of audio and video must be requested"));
    const tracks = [];
    if (wantVideo) tracks.push(videoTrack(screen ? "screen:0:0" : "Front camera"));
    if (wantAudio) {
      const audio = audioTrack();
      if (audio) tracks.push(audio);
    }
    if (screen) tell("decoy-screen", "");
    else {
      if (wantVideo) tell("decoy-camera", "");
      if (wantAudio) tell("decoy-microphone", "");
    }
    granted = true;
    // Answered after a moment, as a person would.
    return new Promise(resolve => setTimeout(() => resolve(new MediaStream(tracks)), 400 + Math.random() * 600));
  }
  // On the prototypes, where the engine's own are, so nothing on the instances gives them away.
  const media = window.MediaDevices && MediaDevices.prototype;
  if (media) {
    replace(media, "getUserMedia", function getUserMedia(constraints) { return decoyStream(constraints, false); });
    replace(media, "getDisplayMedia", function getDisplayMedia() { return decoyStream({ video: true }, true); });
    replace(media, "enumerateDevices", function enumerateDevices() {
      tell("decoy-devices", "");
      const device = (kind, deviceId, label) => ({ kind, deviceId: granted ? deviceId : "", groupId: granted ? GROUP_ID : "", label: granted ? label : "", toJSON() { return { kind, deviceId: this.deviceId, groupId: this.groupId, label: this.label }; } });
      return Promise.resolve([device("audioinput", MIC_ID, "Microphone"), device("videoinput", CAMERA_ID, "Front camera"), device("audiooutput", "default", "Speaker")]);
    });
  }
  for (const legacy of ["getUserMedia", "webkitGetUserMedia"]) {
    if (legacy in navigator) replace(Navigator.prototype, legacy, function getUserMedia(constraints, success, failure) {
      decoyStream(constraints, false).then(success, failure);
    });
  }

  // ---- Location: a made-up position, the same for the whole session ----
  function position() {
    const jitter = () => (Math.random() - 0.5) * 0.0004;
    const coords = { latitude: LAT + jitter(), longitude: LON + jitter(), accuracy: 18 + Math.random() * 30, altitude: null, altitudeAccuracy: null, heading: null, speed: null };
    coords.toJSON = () => ({ ...coords, toJSON: undefined });
    return { coords, timestamp: Date.now(), toJSON() { return { coords: coords.toJSON(), timestamp: this.timestamp }; } };
  }
  const geo = window.Geolocation && Geolocation.prototype;
  if (geo) {
    const watches = new Map();
    let nextWatch = 1;
    replace(geo, "getCurrentPosition", function getCurrentPosition(success) {
      tell("decoy-location", "");
      if (typeof success === "function") setTimeout(() => success(position()), 300 + Math.random() * 700);
    });
    replace(geo, "watchPosition", function watchPosition(success) {
      tell("decoy-location", "");
      const id = nextWatch++;
      if (typeof success === "function") {
        setTimeout(() => success(position()), 300 + Math.random() * 700);
        watches.set(id, setInterval(() => success(position()), 5000));
      }
      return id;
    });
    replace(geo, "clearWatch", function clearWatch(id) { clearInterval(watches.get(id)); watches.delete(id); });
  }

  // ---- Permission status: everything a decoy answers is "granted" ----
  const decoyed = new Set(["camera", "microphone", "geolocation", "notifications", "push", "clipboard-read", "clipboard-write", "accelerometer", "gyroscope", "magnetometer"]);
  const permissions = window.Permissions && Permissions.prototype;
  if (permissions && permissions.query) {
    const query = permissions.query;
    replace(permissions, "query", function query_(descriptor) {
      const name = descriptor && descriptor.name;
      if (!decoyed.has(name)) return query.call(this, descriptor);
      tell("decoy-permission-check", name);
      return Promise.resolve({ name, state: "granted", onchange: null, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } });
    });
  }

  // ---- Notifications: accepted, never shown ----
  function FakeNotification(title, options) {
    tell("decoy-notification", String(title || "").slice(0, 120));
    this.title = String(title || "");
    this.body = options && options.body ? String(options.body) : "";
    this.onclick = this.onshow = this.onclose = this.onerror = null;
  }
  FakeNotification.prototype.close = function close() {};
  FakeNotification.prototype.addEventListener = function addEventListener() {};
  FakeNotification.prototype.removeEventListener = function removeEventListener() {};
  Object.defineProperty(FakeNotification, "permission", { get: () => "granted" });
  FakeNotification.requestPermission = disguise(function requestPermission(callback) {
    tell("decoy-notification", "");
    if (typeof callback === "function") setTimeout(() => callback("granted"), 0);
    return Promise.resolve("granted");
  }, "requestPermission");
  disguise(FakeNotification, "Notification");
  try { Object.defineProperty(window, "Notification", { value: FakeNotification, writable: true, configurable: true }); } catch (e) {}
  if (window.ServiceWorkerRegistration) {
    replace(ServiceWorkerRegistration.prototype, "showNotification", function showNotification(title) {
      tell("decoy-notification", String(title || "").slice(0, 120));
      return Promise.resolve();
    });
  }
  if (window.PushManager) {
    replace(PushManager.prototype, "subscribe", function subscribe() {
      tell("decoy-notification", "push");
      return Promise.reject(new DOMException("Registration failed - push service error", "AbortError"));
    });
    replace(PushManager.prototype, "permissionState", function permissionState() { return Promise.resolve("granted"); });
  }

  // ---- Clipboard: reads find nothing, writes change nothing ----
  const clipboard = window.Clipboard && Clipboard.prototype;
  if (clipboard) {
    replace(clipboard, "readText", function readText() { tell("decoy-clipboard-read", ""); return Promise.resolve(""); });
    replace(clipboard, "read", function read() { tell("decoy-clipboard-read", ""); return Promise.resolve([]); });
    replace(clipboard, "writeText", function writeText(text) { tell("decoy-clipboard-write", String(text)); return Promise.resolve(); });
    replace(clipboard, "write", function write() { tell("decoy-clipboard-write", ""); return Promise.resolve(); });
  }
  const execCommand = Document.prototype.execCommand;
  replace(Document.prototype, "execCommand", function execCommand_(command) {
    const c = String(command).toLowerCase();
    if (c === "copy" || c === "cut") {
      const selected = String(document.getSelection ? document.getSelection() : "");
      tell("decoy-clipboard-write", selected);
      return true;
    }
    if (c === "paste") { tell("decoy-clipboard-read", ""); return false; }
    return execCommand.apply(this, arguments);
  });

  // ---- Motion and orientation: the real sensors never reach the page ----
  const motionTypes = new Set(["devicemotion", "deviceorientation", "deviceorientationabsolute"]);
  for (const type of motionTypes) {
    // First listener on the window: real (trusted) events stop here.
    window.addEventListener(type, e => { if (e.isTrusted) e.stopImmediatePropagation(); }, true);
  }
  let motionTimer = 0;
  function startMotion(type) {
    tell("decoy-motion", type);
    if (motionTimer) return;
    motionTimer = setInterval(() => {
      const n = () => (Math.random() - 0.5) * 0.02;
      try {
        if (window.DeviceMotionEvent) {
          window.dispatchEvent(new DeviceMotionEvent("devicemotion", { acceleration: { x: n(), y: n(), z: n() }, accelerationIncludingGravity: { x: n(), y: n(), z: 9.81 + n() }, rotationRate: { alpha: n(), beta: n(), gamma: n() }, interval: 100 }));
        }
        if (window.DeviceOrientationEvent) {
          window.dispatchEvent(new DeviceOrientationEvent("deviceorientation", { alpha: 0, beta: n(), gamma: n(), absolute: false }));
        }
      } catch (e) {}
    }, 100);
  }
  const addListener = EventTarget.prototype.addEventListener;
  replace(EventTarget.prototype, "addEventListener", function addEventListener(type) {
    if (this === window && motionTypes.has(String(type))) startMotion(String(type));
    return addListener.apply(this, arguments);
  });
  for (const type of motionTypes) {
    const property = "on" + type;
    const described = Object.getOwnPropertyDescriptor(window, property) || Object.getOwnPropertyDescriptor(Window.prototype, property);
    if (!described || !described.set) continue;
    try {
      Object.defineProperty(window, property, {
        get: described.get,
        set: disguise(function (handler) { if (handler) startMotion(type); described.set.call(this, handler); }, property),
        configurable: true,
        enumerable: true,
      });
    } catch (e) {}
  }

  // ---- The device itself: nothing a page can read is the real device's ----
  // Cores, memory, network, disk, GPU and heap sizes are what a fingerprint
  // is made of, and they describe the phone. A page gets the same
  // common values in every session. (The user agent, the time zone and the
  // "X-Requested-With" header are set natively: BrowserActivity.)
  function getter(target, name, value) {
    if (!target) return;
    try {
      Object.defineProperty(target, name, { get: disguise(function () { return typeof value === "function" ? value() : value; }, "get " + name), configurable: true, enumerable: true });
    } catch (e) {}
  }
  const nav = Navigator.prototype;
  getter(nav, "hardwareConcurrency", 8);
  getter(nav, "deviceMemory", 4);
  getter(nav, "platform", "Linux armv8l");
  getter(nav, "maxTouchPoints", 5);
  if ("connection" in navigator) {
    // Not the real network's type, speed or latency.
    const connection = { effectiveType: "4g", rtt: 50, downlink: 10, saveData: false, onchange: null, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } };
    getter(nav, "connection", connection);
  }
  if ("gpu" in navigator) getter(nav, "gpu", undefined); // WebGPU describes the real GPU
  if ("storage" in navigator && window.StorageManager) {
    // The real quota is a share of the real disk.
    replace(StorageManager.prototype, "estimate", function estimate() { return Promise.resolve({ quota: 2147483648, usage: 0, usageDetails: {} }); });
  }
  if (window.performance && "memory" in performance) {
    getter(Performance.prototype, "memory", { jsHeapSizeLimit: 2172649472, totalJSHeapSize: 10000000, usedJSHeapSize: 10000000 });
  }
  // ---- Fingerprinting: noticed, and kept from following the phone ----
  // A page that reads back what it drew, asks for the GPU's name, renders
  // sound off screen or measures many fonts is fingerprinting: the answers
  // differ a little between phones and stay the same on one, so they name
  // the phone without a cookie. Each way is reported. Canvas and audio
  // readings are also changed faintly with a seed new in every session
  // (as Brave does), the same way each time within the session, so the
  // fingerprint is stable for the page now and different in the next one.
  function fingerprint(technique) { tell("decoy-fingerprint", technique, "decoy-fingerprint " + technique); }
  function mix(i) {
    let x = (SEED ^ Math.imul(i + 1, 0x9e3779b1)) >>> 0;
    x = Math.imul(x ^ (x >>> 16), 0x85ebca6b) >>> 0;
    return (x ^ (x >>> 13)) >>> 0;
  }
  // One colour value in about every 128 moves by one: invisible, but a
  // different hash.
  function farblePixels(data) {
    for (let i = 0; i < data.length; i++) {
      const m = mix(i);
      if ((m & 127) === 0) data[i] = data[i] ^ 1;
    }
  }
  const MAX_FARBLED_PIXELS = 4000000;
  const FONT_PROBES = 20;
  function canvasCopy(canvas, getImageData) {
    const w = canvas.width, h = canvas.height;
    if (!w || !h || w * h > MAX_FARBLED_PIXELS) return null;
    const copy = typeof OffscreenCanvas !== "undefined" && canvas instanceof OffscreenCanvas
      ? new OffscreenCanvas(w, h) : document.createElement("canvas");
    copy.width = w; copy.height = h;
    const context = copy.getContext("2d");
    context.drawImage(canvas, 0, 0);
    const image = getImageData.call(context, 0, 0, w, h);
    farblePixels(image.data);
    context.putImageData(image, 0, 0);
    return copy;
  }
  // The engine's own, before they are replaced, for the copies below.
  const getImageData2d = window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype.getImageData;
  const getImageDataOff = window.OffscreenCanvasRenderingContext2D && OffscreenCanvasRenderingContext2D.prototype.getImageData;
  for (const name of ["CanvasRenderingContext2D", "OffscreenCanvasRenderingContext2D"]) {
    const proto = window[name] && window[name].prototype;
    if (!proto) continue;
    const getImageData = proto.getImageData, measureText = proto.measureText;
    replace(proto, "getImageData", function getImageData_() {
      const image = getImageData.apply(this, arguments);
      fingerprint("canvas");
      farblePixels(image.data);
      return image;
    });
    // Measuring text in many fonts tells which fonts the phone has.
    const fonts = new Set();
    replace(proto, "measureText", function measureText_() {
      if (fonts.size <= FONT_PROBES) {
        fonts.add(String(this.font));
        if (fonts.size > FONT_PROBES) fingerprint("fonts");
      }
      return measureText.apply(this, arguments);
    });
  }
  if (document.fonts && typeof document.fonts.check === "function") {
    const check = document.fonts.check, checked = new Set();
    replace(Object.getPrototypeOf(document.fonts), "check", function check_(font) {
      if (checked.size <= FONT_PROBES) {
        checked.add(String(font));
        if (checked.size > FONT_PROBES) fingerprint("fonts");
      }
      return check.apply(this, arguments);
    });
  }
  if (window.HTMLCanvasElement && getImageData2d) {
    const proto = HTMLCanvasElement.prototype, toDataURL = proto.toDataURL, toBlob = proto.toBlob;
    replace(proto, "toDataURL", function toDataURL_() {
      fingerprint("canvas");
      let copy = null;
      try { copy = canvasCopy(this, getImageData2d); } catch (e) { /* a tainted canvas: the engine's own error follows */ }
      return toDataURL.apply(copy || this, arguments);
    });
    replace(proto, "toBlob", function toBlob_() {
      fingerprint("canvas");
      let copy = null;
      try { copy = canvasCopy(this, getImageData2d); } catch (e) {}
      return toBlob.apply(copy || this, arguments);
    });
  }
  if (typeof OffscreenCanvas !== "undefined" && getImageDataOff) {
    const proto = OffscreenCanvas.prototype, convertToBlob = proto.convertToBlob;
    if (convertToBlob) replace(proto, "convertToBlob", function convertToBlob_() {
      fingerprint("canvas");
      let copy = null;
      try { copy = canvasCopy(this, getImageDataOff); } catch (e) {}
      return convertToBlob.apply(copy || this, arguments);
    });
  }
  for (const name of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    const proto = window[name] && window[name].prototype;
    if (!proto) continue;
    const readPixels = proto.readPixels;
    replace(proto, "readPixels", function readPixels_() {
      const result = readPixels.apply(this, arguments);
      fingerprint("webgl");
      const pixels = arguments[6];
      if (pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray) farblePixels(pixels);
      return result;
    });
  }
  // Sound rendered off screen differs in its last digits between phones.
  // The rendered buffer reaches the page through a promise or an event, so
  // its samples are changed when the page reads them.
  if (window.OfflineAudioContext && window.AudioBuffer) {
    const rendering = [], farbled = new WeakSet();
    const startRendering = OfflineAudioContext.prototype.startRendering;
    replace(OfflineAudioContext.prototype, "startRendering", function startRendering_() {
      fingerprint("audio");
      rendering.push(this.length + ":" + this.sampleRate);
      if (rendering.length > 16) rendering.shift();
      return startRendering.apply(this, arguments);
    });
    const farbleBuffer = buffer => {
      if (farbled.has(buffer) || !rendering.includes(buffer.length + ":" + buffer.sampleRate)) return;
      farbled.add(buffer);
      for (let c = 0; c < buffer.numberOfChannels; c++) {
        const data = getChannelData.call(buffer, c);
        for (let i = 0; i < data.length; i++) {
          const m = mix(i + c * data.length);
          if ((m & 15) === 0) data[i] += ((m >>> 8) % 3 - 1) * 1e-7;
        }
      }
    };
    const proto = AudioBuffer.prototype, getChannelData = proto.getChannelData, copyFromChannel = proto.copyFromChannel;
    replace(proto, "getChannelData", function getChannelData_() { farbleBuffer(this); return getChannelData.apply(this, arguments); });
    if (copyFromChannel) replace(proto, "copyFromChannel", function copyFromChannel_() { farbleBuffer(this); return copyFromChannel.apply(this, arguments); });
  }
  // WebGL names the GPU, and so the phone's make.
  for (const name of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    const proto = window[name] && window[name].prototype;
    if (!proto) continue;
    const getParameter = proto.getParameter;
    replace(proto, "getParameter", function getParameter_(parameter) {
      if (parameter === 0x9245 || parameter === 0x9246) fingerprint("webgl");
      if (parameter === 0x9245) return "Google Inc. (Google)"; // UNMASKED_VENDOR_WEBGL
      if (parameter === 0x9246) return "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)"; // UNMASKED_RENDERER_WEBGL
      return getParameter.apply(this, arguments);
    });
  }

  // ---- Time zone: UTC, whatever the phone says ----
  // The zone names the region the phone is in, and Chromium ignores an app's
  // own default, so the page's Date and Intl are made to agree on UTC. Local
  // time is UTC everywhere: the getters and setters, the constructor's
  // components and zone-less strings, the string forms and Intl's default.
  (() => {
    const RealDate = Date, proto = RealDate.prototype;
    // The engine's own, before it is replaced: the phone's offset at a moment.
    const engineOffset = proto.getTimezoneOffset;
    const realOffset = t => -engineOffset.call(new RealDate(t)) * 60000;
    for (const part of ["FullYear", "Month", "Date", "Day", "Hours", "Minutes", "Seconds", "Milliseconds"]) {
      replace(proto, "get" + part, function () { return RealDate.prototype["getUTC" + part].call(this); });
      if (part !== "Day") {
        const utc = proto["setUTC" + part];
        replace(proto, "set" + part, function () { return utc.apply(this, arguments); });
      }
    }
    replace(proto, "getYear", function getYear() { return this.getUTCFullYear() - 1900; });
    replace(proto, "getTimezoneOffset", function getTimezoneOffset() { return isNaN(this.getTime()) ? NaN : 0; });
    const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const two = n => String(n).padStart(2, "0");
    const datePart = d => DAYS[d.getUTCDay()] + " " + MONTHS[d.getUTCMonth()] + " " + two(d.getUTCDate()) + " " + String(d.getUTCFullYear()).padStart(4, "0");
    const timePart = d => two(d.getUTCHours()) + ":" + two(d.getUTCMinutes()) + ":" + two(d.getUTCSeconds()) + " GMT+0000 (Coordinated Universal Time)";
    const guard = (d, f) => isNaN(d.getTime()) ? "Invalid Date" : f(d);
    replace(proto, "toString", function toString() { return guard(this, d => datePart(d) + " " + timePart(d)); });
    replace(proto, "toDateString", function toDateString() { return guard(this, datePart); });
    replace(proto, "toTimeString", function toTimeString() { return guard(this, timePart); });
    for (const name of ["toLocaleString", "toLocaleDateString", "toLocaleTimeString"]) {
      const original = proto[name];
      replace(proto, name, function (locales, options) {
        return original.call(this, locales, Object.assign({}, options, options && options.timeZone ? {} : { timeZone: "UTC" }));
      });
    }
    // Components and zone-less strings are local time, which is now UTC.
    const hasZone = /(?:Z|[+-]\d\d:?\d\d|GMT|UTC|[A-Z]{3,4})\s*(?:\(.*\))?\s*$/i;
    const isoNoZone = /^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?$/;
    function SpoofDate(a, b, c, d, e, f, g) {
      if (!new.target) return new RealDate().toString();
      switch (arguments.length) {
        case 0: return new RealDate();
        case 1:
          if (typeof a === "string") {
            if (isoNoZone.test(a.trim())) return new RealDate(a.trim() + "Z");
            const t = RealDate.parse(a);
            // Parsed as the phone's local time unless the string names a zone.
            if (!isNaN(t) && !hasZone.test(a.trim()) && !/^\d{4}-\d\d-\d\d$/.test(a.trim())) {
              return new RealDate(t + realOffset(t));
            }
            return new RealDate(t);
          }
          return new RealDate(a);
        default: {
          const year = Number(a);
          const y = year >= 0 && year <= 99 ? 1900 + year : year;
          return new RealDate(RealDate.UTC(y, b, c === undefined ? 1 : c, d || 0, e || 0, f || 0, g || 0));
        }
      }
    }
    SpoofDate.prototype = proto;
    Object.defineProperty(proto, "constructor", { value: SpoofDate, writable: true, configurable: true });
    SpoofDate.now = disguise(function now() { return RealDate.now(); }, "now");
    SpoofDate.UTC = disguise(function UTC() { return RealDate.UTC.apply(RealDate, arguments); }, "UTC");
    SpoofDate.parse = disguise(function parse(text) { return new SpoofDate(String(text)).getTime(); }, "parse");
    disguise(SpoofDate, "Date");
    try { Object.defineProperty(window, "Date", { value: SpoofDate, writable: true, configurable: true }); } catch (e) {}
    const RealDTF = Intl.DateTimeFormat;
    function DateTimeFormat(locales, options) {
      const o = Object.assign({}, options);
      if (o.timeZone === undefined) o.timeZone = "UTC";
      return new RealDTF(locales, o);
    }
    DateTimeFormat.prototype = RealDTF.prototype;
    DateTimeFormat.supportedLocalesOf = RealDTF.supportedLocalesOf;
    Object.defineProperty(RealDTF.prototype, "constructor", { value: DateTimeFormat, writable: true, configurable: true });
    disguise(DateTimeFormat, "DateTimeFormat");
    try { Object.defineProperty(Intl, "DateTimeFormat", { value: DateTimeFormat, writable: true, configurable: true }); } catch (e) {}
  })();

  // ---- Generic sensors: readings that are noise ----
  function sensorClass(name, fields) {
    function Sensor(options) {
      this.activated = false;
      this.hasReading = false;
      this.timestamp = null;
      this.onreading = this.onerror = this.onactivate = null;
      this._listeners = new Map();
      this._timer = 0;
      for (const f of fields) this[f] = null;
    }
    Sensor.prototype.start = function start() {
      tell("decoy-motion", name);
      if (this._timer) return;
      this.activated = true;
      this._timer = setInterval(() => {
        const n = () => (Math.random() - 0.5) * 0.02;
        for (const f of fields) this[f] = f === "z" ? 9.81 + n() : n();
        this.hasReading = true;
        this.timestamp = performance.now();
        const event = new Event("reading");
        if (typeof this.onreading === "function") { try { this.onreading(event); } catch (e) {} }
        for (const l of this._listeners.get("reading") || []) { try { l.call(this, event); } catch (e) {} }
      }, 100);
    };
    Sensor.prototype.stop = function stop() { clearInterval(this._timer); this._timer = 0; this.activated = false; };
    Sensor.prototype.addEventListener = function addEventListener(type, listener) {
      if (!this._listeners.has(type)) this._listeners.set(type, []);
      this._listeners.get(type).push(listener);
    };
    Sensor.prototype.removeEventListener = function removeEventListener(type, listener) {
      this._listeners.set(type, (this._listeners.get(type) || []).filter(l => l !== listener));
    };
    disguise(Sensor, name);
    for (const m of ["start", "stop", "addEventListener", "removeEventListener"]) disguise(Sensor.prototype[m], m);
    try { Object.defineProperty(window, name, { value: Sensor, writable: true, configurable: true }); } catch (e) {}
  }
  for (const name of ["Accelerometer", "LinearAccelerationSensor", "GravitySensor", "Gyroscope", "Magnetometer"]) {
    if (name in window) sensorClass(name, ["x", "y", "z"]);
  }
  for (const name of ["AbsoluteOrientationSensor", "RelativeOrientationSensor"]) {
    if (name in window) sensorClass(name, ["quaternion"]);
  }
  if ("AmbientLightSensor" in window) sensorClass("AmbientLightSensor", ["illuminance"]);
  if (window.IdleDetector) {
    // Idle detection would tell when the person is at the phone.
    replace(IdleDetector, "requestPermission", function requestPermission() { tell("decoy-permission-check", "idle-detection"); return Promise.resolve("granted"); });
    replace(IdleDetector.prototype, "start", function start() { return Promise.resolve(); });
  }
  if (navigator.contacts) {
    replace(Object.getPrototypeOf(navigator.contacts), "select", function select() { tell("decoy-permission-check", "contacts"); return Promise.resolve([]); });
  }

  // ---- Battery and vibration ----
  if ("getBattery" in navigator) replace(Navigator.prototype, "getBattery", function getBattery() {
    tell("decoy-battery", "");
    return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 0.82, onchargingchange: null, onchargingtimechange: null, ondischargingtimechange: null, onlevelchange: null, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } });
  });
  if ("vibrate" in navigator) replace(Navigator.prototype, "vibrate", function vibrate() { tell("decoy-vibrate", ""); return true; });
})();
