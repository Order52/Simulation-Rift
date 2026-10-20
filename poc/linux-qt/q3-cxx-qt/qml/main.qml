import QtQuick
import QtQuick.Window
import org.simulationrift.probe

Window {
    visible: false
    RiftCore { id: core }
    Component.onCompleted: {
        for (const url of ["HTTP://Example.COM/a/../b?x#frag", "http://раypal.com/", "http://[::1"])
            console.log("q3: " + url + " -> " + core.canonicalize(url))
        Qt.exit(0)
    }
}
