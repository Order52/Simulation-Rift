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

  // ---- Reporting: one message per kind every few seconds ----
  const lastSent = new Map();
  function tell(kind, detail) {
    const now = Date.now();
    if (now - (lastSent.get(kind) || 0) < 2000) return;
    lastSent.set(kind, now);
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

  // ---- Battery and vibration ----
  if ("getBattery" in navigator) replace(Navigator.prototype, "getBattery", function getBattery() {
    tell("decoy-battery", "");
    return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 0.82, onchargingchange: null, onchargingtimechange: null, ondischargingtimechange: null, onlevelchange: null, addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } });
  });
  if ("vibrate" in navigator) replace(Navigator.prototype, "vibrate", function vibrate() { tell("decoy-vibrate", ""); return true; });
})();
