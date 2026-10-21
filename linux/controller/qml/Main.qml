// The controller's window (docs/architecture.md §9.1). Pages are not shown
// here: each session's page opens in its own sandboxed browser window.
// Every text that can carry web-derived content is plain text.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import org.simulationrift.app

ApplicationWindow {
    id: window
    width: 640
    height: 560
    visible: true
    title: "Simulation-Rift"

    RiftController { id: rift }

    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: rift.refresh()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 10

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: "Each session opens in its own sandbox with no network except Rift's checking proxy, and everything it held is destroyed when it ends."
        }

        RowLayout {
            Layout.fillWidth: true
            TextField {
                id: address
                Layout.fillWidth: true
                placeholderText: "Address"
                text: rift.address
                onAccepted: rift.open(text)
            }
            Button {
                text: "Open"
                onClicked: rift.open(address.text)
            }
            Button {
                text: "End session"
                enabled: rift.active
                onClicked: rift.reset()
            }
        }

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: rift.status
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: rift.intel
        }
        Label {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: rift.traffic
        }

        Label { text: "Refused connections"; font.bold: true }
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            TextArea {
                readOnly: true
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.Wrap
                text: rift.denials
            }
        }

        Label { text: "Quarantined downloads"; font.bold: true }
        ScrollView {
            Layout.fillWidth: true
            Layout.preferredHeight: 100
            TextArea {
                readOnly: true
                textFormat: TextEdit.PlainText
                wrapMode: TextEdit.Wrap
                text: rift.quarantine
            }
        }
    }

    Component.onCompleted: if (rift.address !== "") rift.open(rift.address)
}
