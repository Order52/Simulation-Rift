# Demo script (about ten minutes)

For showing Rift to someone. Every address below is made up for this script or is an ordinary site; none is a live threat. Say what Rift shows. Do not say a link is "safe": Rift never does.

**Before you start:** Android 11 or newer with the current Android System WebView and Chrome (an old WebView is refused on purpose). Install `rift-<version>.apk` from the [latest release](https://github.com/Order52/Simulation-Rift/releases/latest). Over an older Rift it installs in place.

## 0. Starts clean (1 min)
Open Rift. Home shows **Session 1**. If it says **Session cleanup failed**, tap **Retry cleanup**; if it keeps failing, note the line under it. (Releases before 0.11.8 failed here on phones that had opened About or checked for updates.)

## 1. Check a link without opening it (2 min)
Paste each into the Home address field and tap **Check**:

| Address | What Rift says |
|---|---|
| `https://www.wikipedia.org/` | No known threats found |
| `http://secure-paypal-login.verify-account.xyz/signin/update.php?id=1` | Looks dangerous, with the reasons (lookalike of a payment brand, sign-in path on an unrelated host) |
| `https://t.me/prizebot123456_bot` (made up) | Warning: a Telegram bot with a number in its name, the shape fake prize and bank offers use |
| `upi://pay?pa=prize@okbank&pn=Prize&am=4999` | Dangerous app link: asks for a payment |
| `javascript:alert(1)` | Rift won't open this |

Point out: the check ran on the phone and sent nothing anywhere.

## 2. The sealed browser (2 min)
Check `https://www.wikipedia.org/` and tap **Open in Rift**. The page opens in Rift Browser, a separate app with its own Android user ID. Open the live watch card: it lists what the page tried (trackers, other sites it reached).

## 3. Nothing survives (1 min)
Tap **New session**. Android wipes the browser app; Home shows **Session 2**. Open the browser again: no history, no cookies.

## 4. The network lock and the Stop VPN button (2 min)
Home shows **Rift's VPN is on**: a VPN for Rift Browser only, which forwards nothing. Your other apps are not routed through it. Tap **Stop VPN**: the session ends and later sessions are labelled **reduced isolation**. Tap **Turn VPN on** to restore it. Rift has no DNS service of its own.

## 5. Rift AI and updates (1 min)
Security tab: the model's date and what it covers. State the limit: the model is bundled with each release; live updates need the key ceremony ([readiness](reports/readiness.md)).

## If something goes wrong
| You see | Do |
|---|---|
| Browser will not open, "WebView is old" | Update Android System WebView and Chrome |
| **Session cleanup failed** | **Retry cleanup**; on Huawei, Xiaomi, Oppo allow auto-start for Rift Browser |
| Another VPN is active | Turn the network lock back on under Security, or accept reduced isolation |
