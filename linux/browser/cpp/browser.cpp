// The browser host's Qt WebEngine window (docs/architecture.md §9.2).
//
// The page is shown only while its current renderer has passed Rift's
// sandbox check. Every main-frame navigation is decided by the controller,
// every permission is denied, every download is cancelled and handed to
// the controller, and every connection goes to Qt's application proxy:
// the forwarder to the controller's egress proxy. Text from the controller
// is shown as plain text, never as HTML.
//
// The window starts on about:blank, without asking the controller, so that
// a renderer exists and is checked before the controller sends the first
// page. Nothing here logs an address: stderr may outlive the session.

#include "browser.h"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QNetworkProxy>
#include <QPointer>
#include <QPushButton>
#include <QStackedWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWebEngineDownloadRequest>
#include <QWebEnginePage>
#include <QWebEnginePermission>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineView>
#include <QtWebEngineCore/qtwebenginecoreversion.h>
#include <QtWebEngineCore/qwebenginepage.h>

#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "rift-browser/src/bridge.cxxqt.h"

namespace {

constexpr std::uint8_t kProceed = 0;
constexpr std::uint8_t kConfirm = 1;

rust::Str toRust(const std::string &text)
{
    return rust::Str(text.data(), text.size());
}

QString fromRust(const rust::String &text)
{
    return QString::fromUtf8(text.data(), static_cast<qsizetype>(text.size()));
}

class Window;

class Page : public QWebEnginePage
{
public:
    Page(QWebEngineProfile *profile, Window *window);

    // The one URL the user chose to open despite the controller's reasons.
    QUrl confirmed;

protected:
    bool acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) override;
    // Popups open in this page, under the same checks.
    QWebEnginePage *createWindow(WebWindowType) override { return this; }
    // The sub-sandbox has no user files to offer.
    QStringList chooseFiles(FileSelectionMode, const QStringList &, const QStringList &) override
    {
        return {};
    }

private:
    Window *m_window;
    bool m_started = false;
};

class Window : public QMainWindow
{
public:
    Window()
        : m_profile(new QWebEngineProfile(this)) // no storage name: off the record
        , m_page(new Page(m_profile, this))
        , m_view(new QWebEngineView(this))
        , m_stack(new QStackedWidget(this))
        , m_address(new QLineEdit(this))
        , m_message(new QLabel(this))
        , m_continue(new QPushButton(QStringLiteral("Open anyway"), this))
    {
        setWindowTitle(QStringLiteral("Rift session"));
        resize(1100, 800);

        QWebEngineSettings *settings = m_profile->settings();
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, false);
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
        settings->setAttribute(QWebEngineSettings::PluginsEnabled, false);
        settings->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
        settings->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
        m_profile->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies);
        m_profile->setHttpCacheType(QWebEngineProfile::MemoryHttpCache);

        // Before the page is set up, which can start its renderer.
        connect(m_page, &QWebEnginePage::renderProcessPidChanged, this, [this](qint64 pid) {
            checkRenderer(pid);
        });
        m_view->setPage(m_page);

        auto *toolbar = addToolBar(QStringLiteral("Navigation"));
        toolbar->setMovable(false);
        toolbar->addAction(m_view->pageAction(QWebEnginePage::Back));
        toolbar->addAction(m_view->pageAction(QWebEnginePage::Forward));
        toolbar->addAction(m_view->pageAction(QWebEnginePage::Reload));
        toolbar->addWidget(m_address);
        auto *badge = new QLabel(QStringLiteral("  Rift session: no network except Rift's proxy  "), this);
        toolbar->addWidget(badge);

        auto *checking = new QLabel(QStringLiteral("Checking that the page's renderer is sandboxed…"), this);
        checking->setAlignment(Qt::AlignCenter);
        m_stack->addWidget(checking); // 0
        m_stack->addWidget(m_view);   // 1
        auto *interstitial = new QWidget(this);
        auto *layout = new QVBoxLayout(interstitial);
        m_message->setTextFormat(Qt::PlainText);
        m_message->setWordWrap(true);
        m_message->setAlignment(Qt::AlignCenter);
        auto *buttons = new QHBoxLayout();
        auto *back = new QPushButton(QStringLiteral("Go back"), this);
        buttons->addStretch();
        buttons->addWidget(back);
        buttons->addWidget(m_continue);
        buttons->addStretch();
        layout->addStretch();
        layout->addWidget(m_message);
        layout->addLayout(buttons);
        layout->addStretch();
        m_stack->addWidget(interstitial); // 2
        setCentralWidget(m_stack);
        m_stack->setCurrentIndex(0);

        connect(m_address, &QLineEdit::returnPressed, this, [this] {
            load(QUrl::fromUserInput(m_address->text()));
        });
        connect(back, &QPushButton::clicked, this, [this] { showPage(); });
        connect(m_continue, &QPushButton::clicked, this, [this] {
            m_page->confirmed = m_pendingUrl;
            load(m_pendingUrl);
        });
        connect(m_page, &QWebEnginePage::urlChanged, this, [this](const QUrl &url) {
            m_address->setText(url.toDisplayString());
        });
        connect(m_page, &QWebEnginePage::loadFinished, this, [this](bool ok) {
            std::fputs(ok ? "rift-browser: page loaded\n" : "rift-browser: page did not load\n", stderr);
            // In case the engine started the renderer before it was watched.
            const qint64 pid = m_page->renderProcessPid();
            if (pid == 0)
                std::fputs("rift-browser: the engine reports no renderer\n", stderr);
            else if (pid != m_checkedPid)
                checkRenderer(pid);
        });
        connect(m_page, &QWebEnginePage::titleChanged, this, [this](const QString &title) {
            setWindowTitle(QStringLiteral("Rift session: %1").arg(title));
        });
        connect(m_page, &QWebEnginePage::permissionRequested, this, [](QWebEnginePermission permission) {
            permission.deny();
        });
        connect(m_profile, &QWebEngineProfile::downloadRequested, this, [this](QWebEngineDownloadRequest *download) {
            const std::string url = download->url().toString(QUrl::FullyEncoded).toStdString();
            const std::string agent = m_profile->httpUserAgent().toStdString();
            download->cancel();
            download_requested(toRust(url), toRust(agent));
        });
    }

    void load(const QUrl &url) { m_page->load(url); }

    void showInterstitial(std::uint8_t kind, const QUrl &url, const QString &text)
    {
        m_pendingUrl = url;
        m_message->setText(text.isEmpty() ? QStringLiteral("Rift blocked this page.") : text);
        m_continue->setVisible(kind == kConfirm);
        m_stack->setCurrentIndex(2);
    }

    void showPage() { m_stack->setCurrentIndex(m_verifiedPid != 0 && m_verifiedPid == m_page->renderProcessPid() ? 1 : 0); }

protected:
    void closeEvent(QCloseEvent *event) override
    {
        event->accept();
        QApplication::quit();
    }

private:
    void checkRenderer(qint64 pid)
    {
        m_stack->setCurrentIndex(0);
        m_verifiedPid = 0;
        m_checkedPid = pid;
        if (pid == 0)
            return; // the renderer ended; a new one is checked when it starts
        const rust::String failure = renderer_started(pid);
        std::fputs(failure.empty() ? "rift-browser: renderer sandboxed\n" : "rift-browser: renderer not sandboxed\n",
                   stderr);
        if (failure.empty()) {
            m_verifiedPid = pid;
            m_stack->setCurrentIndex(1);
        } else {
            // The controller was told and ends the session.
            m_message->setText(fromRust(failure));
            m_continue->setVisible(false);
            m_stack->setCurrentIndex(2);
            m_view->setEnabled(false);
        }
    }

    QWebEngineProfile *m_profile;
    Page *m_page;
    QWebEngineView *m_view;
    QStackedWidget *m_stack;
    QLineEdit *m_address;
    QLabel *m_message;
    QPushButton *m_continue;
    QUrl m_pendingUrl;
    qint64 m_verifiedPid = 0;
    qint64 m_checkedPid = 0;
};

Page::Page(QWebEngineProfile *profile, Window *window)
    : QWebEnginePage(profile, window)
    , m_window(window)
{
}

bool Page::acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame)
{
    // Subframes are not decided here; every connection they make still goes
    // through the controller's proxy, which screens it.
    if (!isMainFrame)
        return true;
    if (!m_started) {
        m_started = true;
        if (url == QUrl(QStringLiteral("about:blank")))
            return true; // the bootstrap page: no network, and its renderer gets checked
    }
    const bool confirmedByUser = !confirmed.isEmpty() && url == confirmed;
    confirmed = QUrl();
    const std::string text = url.toString(QUrl::FullyEncoded).toStdString();
    const NavigationAnswer answer = decide(toRust(text), isMainFrame, type == NavigationTypeLinkClicked,
                                           type == NavigationTypeRedirect, confirmedByUser);
    if (answer.kind == kProceed)
        return true;
    m_window->showInterstitial(answer.kind, url, fromRust(answer.text));
    return false;
}

// Loads and a close may arrive from the channel thread before the window
// exists; they wait here until it does.
std::mutex g_lock;
QPointer<Window> g_window;
std::vector<std::string> g_early;
bool g_closeEarly = false;

} // namespace

std::int32_t run_browser(std::uint16_t proxy_port)
{
    static int argc = 1;
    static char name[] = "rift-browser";
    static char *argv[] = {name, nullptr};
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("rift-browser"));
    // Before any profile exists: every connection goes to the forwarder.
    QNetworkProxy::setApplicationProxy(
        QNetworkProxy(QNetworkProxy::HttpProxy, QStringLiteral("127.0.0.1"), proxy_port));

    Window window;
    window.show();
    std::vector<std::string> early;
    bool closeEarly = false;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        g_window = &window;
        early.swap(g_early);
        closeEarly = g_closeEarly;
    }
    if (closeEarly)
        return 0;
    window.load(QUrl(QStringLiteral("about:blank")));
    for (const std::string &url : early)
        window.load(QUrl(QString::fromStdString(url)));
    const int code = QApplication::exec();
    std::lock_guard<std::mutex> guard(g_lock);
    g_window = nullptr;
    return code;
}

void post_load(rust::Str url)
{
    const std::string text(url.data(), url.size());
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_window) {
        g_early.push_back(text);
        return;
    }
    QPointer<Window> window = g_window;
    QMetaObject::invokeMethod(window, [window, text] {
        if (window)
            window->load(QUrl(QString::fromStdString(text)));
    }, Qt::QueuedConnection);
}

void post_close()
{
    std::lock_guard<std::mutex> guard(g_lock);
    if (!g_window) {
        g_closeEarly = true;
        return;
    }
    QMetaObject::invokeMethod(qApp, [] { QApplication::quit(); }, Qt::QueuedConnection);
}

rust::String engine_version()
{
    const std::string version = std::string("Qt WebEngine ") + QTWEBENGINECORE_VERSION_STR + " (Chromium "
        + qWebEngineChromiumVersion() + ")";
    return rust::String(version);
}
