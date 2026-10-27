# Rift user guide

How to install Rift and use each of its screens. For how it works inside, see [architecture.md](architecture.md); for what has been tested and where, see [STATUS.md](../STATUS.md).

> Rift is in development and has not been audited. It never calls a link or a file "safe": the best it says is that it found nothing.

## Contents

1. [Install](#1-install)
2. [First launch](#2-first-launch)
3. [Check a link](#3-check-a-link)
4. [Open a link in the sealed browser](#4-open-a-link-in-the-sealed-browser)
5. [Files](#5-files)
6. [The tabs](#6-the-tabs)
7. [Updates](#7-updates)
8. [Troubleshooting](#8-troubleshooting)
9. [What Rift does not do](#9-what-rift-does-not-do)

## 1. Install

Rift needs Android 11 or newer on an arm64 phone (nearly every phone made since 2017).

1. Download `rift-<version>.apk` from the [latest release](https://github.com/Order52/Simulation-Rift/releases/latest).
2. Optionally, check its SHA-256 against the one in the release notes.
3. Open the file on the phone and allow your browser or file manager to install apps when Android asks.

Every release is signed with the same certificate (SHA-256 `8b5952712e7ceda065f558e1de902e12b97027a3244181f8d0330fbc6a47ee8b`), so an update installs over the last version and keeps your settings.

The release also has `rift-browser-<version>.apk`. You only need it if your phone will not let Rift install its browser (see [Troubleshooting](#8-troubleshooting)).

## 2. First launch

Rift is two apps: **Rift** (the controller, which checks links and holds your settings) and **Rift Browser** (the sealed browser). Rift carries the browser inside it.

1. Open Rift. It asks to install Rift Browser; Android asks you to allow Rift to install apps. Allow it, then confirm the install.
2. Tap **Turn on protection**. Android asks to let Rift set up a VPN. This VPN is the **network lock**: it applies only to Rift Browser and drops all of its traffic, so the browser's only way out is Rift's checking proxy on the phone. Your other apps are not affected, and nothing is sent to a VPN server.

The word next to Rift's name at the top of the home screen says whether browsing is protected now (for example **Setup** while the browser is missing, **Stopped** if something failed).

Rift asks for no account and no password, and keeps nothing after a session.

## 3. Check a link

Paste or type a link in **Check or open a link** on the Home tab, or share a link to Rift from any app (a message, an email, a browser). A shared message can hold other text; Rift finds the link in it, including defanged ones such as `hxxps://example[.]com`.

A link shared from another app gets a sheet over that app, so you don't have to leave it.

### The verdict

| Verdict | Meaning |
|---|---|
| **Known malicious** | In Rift's signed threat database |
| **Listed as dangerous** | On a community threat list you turned on (Security tab) |
| **Looks dangerous** / **Warning signs** | Rift's address checks or Rift AI found problems |
| **Rift won't open this** | Blocked by Rift's policy; the reason is given |
| **No known threats found** | Nothing found. This is not a promise the link is harmless |

Under the verdict are its reasons, for example a lookalike of a well-known site (`paypa1-login.com`), a link shortener, a link that hides its real host, or what **Rift AI** thinks of the address: a risk score out of 100 with up to three reasons. Rift AI is advice: it never blocks a link by itself.

The check runs on the phone and contacts nobody, so the sender cannot tell you looked at the link.

### Tools under the verdict

- **Remove the tracking**: takes off tracking parameters (`fbclid`, `gclid`, `utm_…` and others). Each one is named, with who added it and what it tells them.
- **Clean links**, **Use HTTPS**, **Remove everything after ?**, **Edit**: change the link. Each change is checked again, and **Undo** puts it back.
- **Where it goes**: follows the link's redirects without loading any page, checks every hop before contacting it, and shows the most serious verdict along the way. Useful for shortened links.
- **Check the live page**: loads the page out of sight for 10 seconds in a new sealed session, then reports where it went, what it asked for, the trackers and sites it reached, and Rift AI's reading of the page. Unlike plain Check, this does contact the site.
- **Copy**, **Share**, or open the link in another app (after a warning).
- **Open in Rift**: opens it in the sealed browser.

A link that would open another app (a payment, a wallet connection, a Telegram sign-in, a settings screen) is explained: which app it would open and what it asks that app to do.

## 4. Open a link in the sealed browser

**Open in Rift** opens the link in Rift Browser, in a new **session**. A session is everything the browser holds: pages, cookies, downloads. It is thrown away when you start a new one.

### The live watch

While a page is open, the bar at the top of the browser shows what the page has tried, as **Danger**, **Warning** or **Nothing suspicious seen so far**. Tap it for the list. It notes, for example:

- a page or a part of one from an address the threat database or a threat list names (Rift refuses to load it);
- a page that tried to reach your local network or router (refused);
- a connection around the proxy (WebRTC; it has nowhere to go);
- a download, and what its scan found;
- every device feature the page asked for;
- the tracking services it reached, with what each records and how to stop it;
- Rift AI's reading of the page: a password form that sends to another site, links that go nowhere, a brand name that does not match the site, urgent "your account is locked" wording. It warns before you type anything.

The watch comes only from what Rift itself enforced, never from what the page says about itself.

### Decoys

A page that asks for the camera, microphone, screen, location, files, notifications, clipboard, motion sensors or battery is told yes and gets something made up: a dim room on video, near-silence, a position near a city centre, a generated photo, an empty clipboard. The browser holds none of these permissions, so nothing real can be given. The watch lists what the page was after.

### Before a page loads

- A listed address is blocked, with the reason. You can still open it on purpose after a warning, in a new session that lets only that host through, under a red bar.
- An address Rift AI rates **High**, or a lookalike, asks before loading.
- Links that try to open another app by themselves are blocked.
- If the phone's Android System WebView is missing a fix for a Chromium bug attackers are using, Rift refuses to open pages and says which update fixes it. Update **Android System WebView** from the Play Store.

### Ending a session

On the Home tab, **New session** destroys the current one: Android wipes the browser app completely, and Rift checks that the fresh browser holds no file. A link shared from another app always starts a new session if the current one has loaded a page.

If cleanup fails, the Home tab says **Session cleanup failed** with **Retry cleanup**. Check keeps working meanwhile, but no page opens until cleanup succeeds.

## 5. Files

Downloads in the browser, and files shared to Rift, go into an encrypted quarantine for the current session (the **Files** card on the Home tab). Each one is scanned in an isolated worker, a process with no files and no network.

- **Images and PDFs** are drawn by a worker and shown as pictures; nothing in them runs.
- **Text** is shown as plain text, never run.
- A file whose contents don't match its name is flagged, including an Android app under another name.

Files cannot be exported, and they are gone when the session ends.

## 6. The tabs

### Home

The link field, the session (its state, **New session**, the live watch while a page is open) and the session's files.

### Filters

- **Block ads and annoyances**: blocks ads and trackers and hides cookie banners and pop-ups in the browser.
- **Lists**: the community lists to use (EasyList, uBlock Origin, Fanboy, AdGuard and others). Nothing is downloaded until you tap **Download the lists**; each list has its own switch.
- **Keep the lists up to date**: refreshes the downloaded lists daily.
- **Skip sign-ins and pop-ups**: takes down sign-in walls and dismisses pages' dialog boxes.
- **Your own rules**: add rules in the usual ad-blocker syntax, then **Save rules**.
- **Clean links**: **Download the rules** gets the ClearURLs rules Check uses to remove tracking (Check also offers **Get them** when they are missing).

### Activity

- **This week**: counts per day of threats blocked, dangerous files, warnings and links checked. Only the numbers are kept, never the links.
- **Remember checked links**: an optional history of links you checked, encrypted on the phone. Tap one to check it again; **Clear the history** deletes it.

### Security

- **Protection** and **Network lock**: the state of the lock. If you need your own VPN, turn the lock off: sessions then run with **reduced isolation**, labelled as such, and still only through Rift's proxy. Rift never takes the VPN back without you.
- **Extra isolation** (optional, with [Shizuku](https://shizuku.rikka.app) or root): Android ignores the browser's clipboard and itself wipes the browser at each reset; with root, a firewall also keeps the browser to Rift's proxy. Each change is checked after it is made and undone when you switch it off.
- **Threat database**: the signed database Check and the browser use. Release builds can **Check for an update** or **Import an update folder…**; every update is verified before it is installed. (Until the project's signing ceremony is held, a release build has no trusted root and says so.)
- **Threat lists for Check**: HaGeZi, Phishing Army, uBlock Origin badware and StevenBlack. **Download the lists** once; they then update themselves.

### About

- **Appearance**: follow the phone, or always light or dark. In dark, pages without a dark style of their own are darkened too.
- **Updates**: see [Updates](#7-updates).
- **This install**: the versions of Rift, the browser, the threat database and the filter lists, and what Rift sends by itself (only update requests: Rift's own, and the lists you turned on).
- **Open-source licences**.

## 7. Updates

Under **About → Updates**:

| Option | What it does | Default |
|---|---|---|
| **Check when Rift opens** | Each time you open Rift it asks GitHub for its latest release. If there is a newer one, a dialog offers it: tap **Update** to install it, or **Later** | On |
| **Update Rift by itself** | Once a day Rift checks, downloads and installs a newer release. The first time, Android asks you to confirm; after that (Android 12 and newer) Rift updates while you are not using it | On |
| **Check for updates** | Checks right away, whatever the switches. If there is a newer release the button becomes **Update now** | |

Every update is accepted only if its SHA-256 matches the one published with the release and it is signed with Rift's own certificate; Android checks the signature again. The browser is updated together with Rift.

The first time Rift installs an update, Android may ask you to allow Rift to install apps. The dialog has an **Allow** button that opens that setting.

Instead, you can let [Obtainium](https://obtainium.imranr.dev) update Rift: add `https://github.com/Order52/Simulation-Rift` with `^rift-\d` under **Filter APKs by regular expression**.

Threat lists, filter lists and link-cleaning rules update themselves daily once downloaded, independently of app updates.

## 8. Troubleshooting

| Problem | What to do |
|---|---|
| Rift cannot install Rift Browser (some Huawei phones) | Install `rift-browser-<version>.apk` from the same release by hand, then open Rift |
| Rift Browser does not start (Huawei's **App launch**, other battery managers) | Rift tries a windowless screen to start it, and names the setting if that is refused. Allow Rift Browser to start under Settings → Battery → App launch (or your phone's equivalent) |
| Pages won't open: "reduced isolation" or the lock is off | Another VPN took over. Turn the network lock back on under Security, or choose reduced isolation for this session |
| Pages won't open: WebView is missing a fix | Update **Android System WebView** (and Chrome) from the Play Store |
| **Session cleanup failed** | Tap **Retry cleanup**. On a full phone, free some space first |
| An update says it could not install | Tap **Try again** in the dialog, or **Check for updates** later. Check that Rift is allowed to install apps |
| Check says **Not fully scanned** | One of the checks failed or timed out. Rift doesn't treat that as clean; try again later |

## 9. What Rift does not do

- It is **not an antivirus**, a virtual machine or a malware lab. It never runs downloaded programs.
- It does **not hide your IP address** from the sites you open.
- It does **not see inside HTTPS** traffic; the proxy checks destinations, not contents.
- Without root, code that escapes the web engine could still reach **local servers of other apps** on the phone (loopback), which no Android VPN covers.
- A WebView exploit still has the **current session's** browsing data.
- It is **not a guarantee**. The full list of known limits is in [architecture §24](architecture.md#24-residual-risk-register).

Report a vulnerability privately: see [SECURITY.md](../SECURITY.md).
