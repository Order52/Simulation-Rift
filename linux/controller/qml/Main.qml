// The controller's window (docs/architecture.md §9.1). Pages are not shown
// here: each session's page opens in its own sandboxed browser window.
// Every text that can carry web-derived content is plain text.
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import org.simulationrift.app

ApplicationWindow {
    id: window
    width: 640
    height: 820
    visible: true
    title: "Simulation-Rift"

    RiftController { id: rift }

    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: rift.refresh()
    }

    // Previews show only what Rift made: escaped text, or a PNG encoded
    // from the pixels an isolated worker decoded.
    Connections {
        target: rift
        function onPreviewSerialChanged() { preview.open() }
    }
    Dialog {
        id: preview
        title: rift.previewTitle
        modal: true
        anchors.centerIn: parent
        width: parent.width - 32
        height: parent.height - 32
        standardButtons: Dialog.Close
        ColumnLayout {
            anchors.fill: parent
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                textFormat: Text.PlainText
                text: rift.previewNote
                visible: text !== ""
            }
            Image {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: rift.previewImage !== ""
                source: rift.previewImage
                fillMode: Image.PreserveAspectFit
                cache: false
                Accessible.role: Accessible.Graphic
                Accessible.name: status === Image.Ready ? "Preview image" : "Preview image not shown"
            }
            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: rift.previewText !== ""
                TextArea {
                    readOnly: true
                    textFormat: TextEdit.PlainText
                    wrapMode: TextEdit.Wrap
                    font.family: "monospace"
                    text: rift.previewText
                }
            }
        }
    }
    FolderDialog {
        id: importFrom
        title: "Import a threat database update"
        onAccepted: rift.importIntel(selectedFolder)
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
                Accessible.name: placeholderText
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
        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                textFormat: Text.PlainText
                text: rift.intel
            }
            Button {
                text: "Import an update…"
                onClicked: importFrom.open()
            }
            Button {
                text: "Check for an update"
                visible: rift.canUpdate
                onClicked: rift.checkForUpdate()
            }
        }
        Label {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: rift.traffic
        }

        RowLayout {
            Layout.fillWidth: true
            visible: rift.active
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                textFormat: Text.PlainText
                text: "Local network hosts allowed this session: " + (rift.localHosts === "" ? "none" : rift.localHosts)
            }
            TextField {
                id: localHost
                placeholderText: "Host name"
                Accessible.name: placeholderText
                onAccepted: allowHost.clicked()
            }
            Button {
                id: allowHost
                text: "Allow"
                onClicked: { rift.allowLocalHost(localHost.text); localHost.clear() }
            }
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

        Label { text: "Quarantined downloads (destroyed with the session)"; font.bold: true }
        ListView {
            Layout.fillWidth: true
            Layout.preferredHeight: 110
            clip: true
            model: rift.quarantine
            delegate: RowLayout {
                id: row
                required property string modelData
                required property int index
                width: ListView.view.width
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    textFormat: Text.PlainText
                    text: row.modelData
                }
                Button {
                    text: "Preview"
                    onClicked: rift.preview(row.index)
                }
            }
        }
    }

    Component.onCompleted: if (rift.address !== "") rift.open(rift.address)
}
