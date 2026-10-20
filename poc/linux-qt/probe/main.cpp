// PoC Q1/Q4 (Phase 5, Qt): loads one page in Qt WebEngine and reports what
// this process can see of the engine's processes, so the run script can
// compare it with what the host sees (the ground truth).
//
// Usage: qt-probe <url> [seconds to stay open after the load]
// Prints one line per fact, prefixed "probe:", and exits 0 when the page
// loaded, 3 when it did not, 4 on a timeout.

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>
#include <QUrl>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineView>

#include <cstdio>
#include <unistd.h>

namespace {

void say(const QString &line)
{
    std::printf("probe: %s\n", qPrintable(line));
    std::fflush(stdout);
}

QString readFirstLine(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QStringLiteral("unreadable");
    return QString::fromUtf8(file.readLine()).trimmed();
}

QString statusField(const QString &pid, const QString &key)
{
    QFile file(QStringLiteral("/proc/%1/status").arg(pid));
    if (!file.open(QIODevice::ReadOnly))
        return QStringLiteral("unreadable");
    // /proc files report size 0, so QFile::atEnd() is true before any read:
    // read the whole file instead of line by line.
    const QStringList lines = QString::fromUtf8(file.readAll()).split(QLatin1Char('\n'));
    for (const QString &line : lines) {
        if (line.startsWith(key + QLatin1Char(':')))
            return line.mid(key.size() + 1).trimmed();
    }
    return QStringLiteral("absent");
}

QString namespaceOf(const QString &pid, const char *kind)
{
    const QString target = QFileInfo(QStringLiteral("/proc/%1/ns/%2").arg(pid, QLatin1String(kind))).symLinkTarget();
    return target.isEmpty() ? QStringLiteral("unreadable") : QFileInfo(target).fileName();
}

// Every process this process can see whose executable is the web engine's.
void reportVisibleEngineProcesses()
{
    const QString self = QString::number(getpid());
    int seen = 0;
    for (const QString &pid : QDir(QStringLiteral("/proc")).entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        bool numeric = false;
        pid.toInt(&numeric);
        if (!numeric)
            continue;
        const QString comm = readFirstLine(QStringLiteral("/proc/%1/comm").arg(pid));
        if (!comm.startsWith(QLatin1String("QtWebEngineProc")))
            continue;
        ++seen;
        QStringList fresh;
        for (const char *kind : {"user", "mnt", "pid", "net", "ipc"}) {
            if (namespaceOf(pid, kind) != namespaceOf(self, kind))
                fresh << QLatin1String(kind);
        }
        say(QStringLiteral("inside sees pid %1 (%2): Seccomp=%3 filters=%4 (mine %5) NoNewPrivs=%6 new_namespaces=%7")
                .arg(pid, comm, statusField(pid, QStringLiteral("Seccomp")),
                     statusField(pid, QStringLiteral("Seccomp_filters")),
                     statusField(self, QStringLiteral("Seccomp_filters")),
                     statusField(pid, QStringLiteral("NoNewPrivs")), fresh.join(QLatin1Char(','))));
    }
    say(QStringLiteral("inside sees %1 engine processes").arg(seen));
}

} // namespace

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    if (argc < 2) {
        say(QStringLiteral("usage: qt-probe <url> [seconds]"));
        return 2;
    }
    const QUrl url(QString::fromLocal8Bit(argv[1]));
    const int linger = argc > 2 ? QString::fromLocal8Bit(argv[2]).toInt() : 20;

    say(QStringLiteral("qt %1, pid %2, QTWEBENGINE_DISABLE_SANDBOX=%3")
            .arg(QLatin1String(qVersion()))
            .arg(getpid())
            .arg(qEnvironmentVariable("QTWEBENGINE_DISABLE_SANDBOX", QStringLiteral("unset"))));

    // Off the record: nothing is written to disk, as in a Rift session.
    QWebEngineProfile profile;
    QWebEnginePage page(&profile);
    QWebEngineView view;
    view.setPage(&page);
    view.resize(800, 600);
    view.show();

    QObject::connect(&page, &QWebEnginePage::loadFinished, &app, [&](bool ok) {
        say(QStringLiteral("loaded=%1 title=%2 renderer pid (as the engine reports it)=%3")
                .arg(ok ? QStringLiteral("yes") : QStringLiteral("no"), page.title())
                .arg(page.renderProcessPid()));
        reportVisibleEngineProcesses();
        // The run script probes from the host while the page stays open.
        say(QStringLiteral("ready"));
        QTimer::singleShot(linger * 1000, &app, [&app, ok] { app.exit(ok ? 0 : 3); });
    });
    QObject::connect(&page, &QWebEnginePage::renderProcessTerminated, &app,
                     [](QWebEnginePage::RenderProcessTerminationStatus status, int code) {
                         say(QStringLiteral("renderer terminated: status %1 code %2").arg(int(status)).arg(code));
                     });
    QTimer::singleShot(120 * 1000, &app, [&app] {
        say(QStringLiteral("timeout"));
        app.exit(4);
    });
    page.load(url);
    return app.exec();
}
