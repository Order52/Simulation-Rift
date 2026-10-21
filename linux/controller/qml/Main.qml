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

    // The vault locks after five minutes without a vault action, and when
    // the window is minimized or hidden (§14.2).
    Timer {
        id: vaultIdle
        interval: 5 * 60 * 1000
        running: rift.vault === "unlocked"
        onTriggered: rift.lockVault()
    }
    onVisibilityChanged: if (visibility === Window.Minimized || visibility === Window.Hidden) rift.lockVault()
    function touchVault() { vaultIdle.restart() }

    property int exporting: -1
    Dialog {
        id: exportWarning
        title: "Export a kept file"
        modal: true
        anchors.centerIn: parent
        width: Math.min(parent.width - 32, 480)
        Label {
            width: parent.width
            wrapMode: Text.Wrap
            text: "The exported copy leaves Rift's protection. It is the original file, not made safe: opening it outside Rift can harm this computer, whatever its scan said."
        }
        footer: DialogButtonBox {
            Button { text: "Export anyway"; DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole }
            Button { text: "Cancel"; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole }
        }
        onAccepted: exportTarget.open()
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
    FileDialog {
        id: exportTarget
        title: "Export to"
        fileMode: FileDialog.SaveFile
        onAccepted: { window.touchVault(); rift.exportKept(window.exporting, selectedFile) }
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
                Button {
                    text: "Keep in vault"
                    enabled: rift.vault === "unlocked"
                    onClicked: { window.touchVault(); rift.keep(row.index) }
                }
            }
        }

        Label { text: "Vault"; font.bold: true }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: rift.vault === "missing" ? "No vault yet. Choose a passphrase of 10 characters or more; it cannot be recovered."
                : rift.vault === "locked" ? "The vault is locked."
                : rift.vault === "unlocked" ? "The vault is unlocked. Kept files are encrypted, and still untrusted."
                : "This vault was made by a platform key Linux does not have."
        }
        RowLayout {
            Layout.fillWidth: true
            visible: rift.vault === "missing" || rift.vault === "locked"
            TextField {
                id: passphrase
                Layout.fillWidth: true
                echoMode: TextInput.Password
                placeholderText: "Passphrase"
                onAccepted: vaultAction.clicked()
            }
            Button {
                id: vaultAction
                text: rift.vault === "missing" ? "Create" : "Unlock"
                onClicked: {
                    if (rift.vault === "missing") rift.createVault(passphrase.text)
                    else rift.unlockVault(passphrase.text)
                    passphrase.clear()
                }
            }
        }
        Button {
            text: "Lock"
            visible: rift.vault === "unlocked"
            onClicked: rift.lockVault()
        }
        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: rift.vaultStatus
            visible: text !== ""
        }
        ListView {
            Layout.fillWidth: true
            Layout.preferredHeight: 130
            clip: true
            visible: rift.vault === "unlocked"
            model: rift.kept
            delegate: RowLayout {
                id: keptRow
                required property string modelData
                required property int index
                width: ListView.view.width
                Label {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    textFormat: Text.PlainText
                    text: keptRow.modelData
                }
                Button {
                    text: "Export…"
                    onClicked: { window.touchVault(); window.exporting = keptRow.index; exportWarning.open() }
                }
                Button {
                    text: "Delete"
                    onClicked: { window.touchVault(); rift.removeKept(keptRow.index) }
                }
            }
        }
    }

    Component.onCompleted: if (rift.address !== "") rift.open(rift.address)
}
