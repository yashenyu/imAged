import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import Qt.labs.platform 1.1
import QtQuick.Window 2.15

ApplicationWindow {
    id: window
    visible: true
    width: 900
    height: 700
    title: "ImAged - Time-Limited Image Encryption"
    color: "#ffffff" // clean white background
    
    // Properties for binding to Python backend
    property string imageUrl: pythonApi.imageUrl
    property string statusText: pythonApi.statusText
    property int defaultTtlHours: pythonApi.defaultTtlHours
    property string ntpServer: pythonApi.ntpServer
    property string outputDir: pythonApi.outputDir
    property int progress: pythonApi.progress
    property int total: pythonApi.total

    FolderDialog {
        id: folderDialog
        title: "Select Folder for Batch Conversion"
        onAccepted: pythonApi.batchConvert(folder)
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 20

        // Header
        Rectangle {
            Layout.fillWidth: true
            height: 50
            color: "#f0f0f0"
            radius: 4
            border.color: "#cccccc"

            RowLayout {
                anchors.fill: parent
                anchors.margins: 10

                Text {
                    text: "ImAged"
                    font.pixelSize: 22
                    font.weight: Font.Bold
                    color: "#333333"
                }

                Item { Layout.fillWidth: true }

                Text {
                    text: "Time-Limited Image Encryption"
                    font.pixelSize: 14
                    color: "#666666"
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 20

            // Left panel
            ColumnLayout {
                Layout.preferredWidth: 500
                Layout.fillHeight: true
                spacing: 15

                // Image display
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: "#fafafa"
                    radius: 4
                    border.color: "#cccccc"

                    Image {
                        id: imageDisplay
                        anchors.fill: parent
                        anchors.margins: 10
                        source: imageUrl
                        fillMode: Image.PreserveAspectFit
                        cache: false

                        Rectangle {
                            anchors.fill: parent
                            color: "#f5f5f5"
                            visible: !imageDisplay.source || imageDisplay.source === ""
                            
                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 8

                                Text {
                                    text: "📷"
                                    font.pixelSize: 40
                                    horizontalAlignment: Text.AlignHCenter
                                }

                                Text {
                                    text: "No image loaded"
                                    font.pixelSize: 14
                                    color: "#777"
                                    horizontalAlignment: Text.AlignHCenter
                                }

                                Text {
                                    text: "Open an image or TTL file to get started"
                                    font.pixelSize: 12
                                    color: "#999"
                                    horizontalAlignment: Text.AlignHCenter
                                }
                            }
                        }
                    }
                }

                // Image controls
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8

                    Button {
                        text: "Open Image"
                        Layout.fillWidth: true
                        height: 35
                        onClicked: pythonApi.openImage()
                    }

                    Button {
                        text: "Open TTL"
                        Layout.fillWidth: true
                        height: 35
                        onClicked: pythonApi.openTtl()
                    }

                    Button {
                        text: "Save PNG"
                        Layout.fillWidth: true
                        height: 35
                        onClicked: pythonApi.saveAsPng()
                    }
                }
            }

            // Right panel
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 15

                // TTL Conversion
                GroupBox {
                    title: "TTL Conversion"
                    Layout.fillWidth: true

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8

                        Button {
                            text: "Convert to TTL (Default: " + defaultTtlHours + "h)"
                            Layout.fillWidth: true
                            height: 35
                            onClicked: pythonApi.convertToTtl()
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 120
                            color: "#fafafa"
                            radius: 4
                            border.color: "#cccccc"

                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 8
                                spacing: 6

                                Text {
                                    text: "Custom Expiry:"
                                    font.pixelSize: 12
                                    font.weight: Font.Bold
                                    color: "#333"
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 5

                                    SpinBox { id: yearSpin; from: 2024; to: 2030; value: 2024; editable: true; Layout.fillWidth: true }
                                    Text { text: "-" }
                                    SpinBox { id: monthSpin; from: 1; to: 12; value: 1; editable: true; Layout.fillWidth: true }
                                    Text { text: "-" }
                                    SpinBox { id: daySpin; from: 1; to: 31; value: 1; editable: true; Layout.fillWidth: true }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 5

                                    SpinBox { id: hourSpin; from: 0; to: 23; value: 12; editable: true; Layout.fillWidth: true }
                                    Text { text: ":" }
                                    SpinBox { id: minuteSpin; from: 0; to: 59; value: 0; editable: true; Layout.fillWidth: true }
                                    Item { Layout.fillWidth: true }
                                    Button {
                                        text: "Convert"
                                        height: 28
                                        onClicked: {
                                            pythonApi.convertToTtlCustom(
                                                yearSpin.value, monthSpin.value, 
                                                daySpin.value, hourSpin.value, minuteSpin.value
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        Button {
                            text: "Batch Convert Folder"
                            Layout.fillWidth: true
                            height: 35
                            onClicked: folderDialog.open()
                        }

                        ProgressBar {
                            id: progressBar
                            Layout.fillWidth: true
                            height: 18
                            visible: total > 0
                            value: total > 0 ? progress / total : 0
                        }

                        Text {
                            text: total > 0 ? "Progress: " + progress + "/" + total : ""
                            font.pixelSize: 12
                            color: "#666"
                            visible: total > 0
                        }
                    }
                }

                // Settings
                GroupBox {
                    title: "Settings"
                    Layout.fillWidth: true

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 8

                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: "Default TTL (hours):"; Layout.preferredWidth: 120; font.pixelSize: 12 }
                            SpinBox { id: defaultTtlSpin; from: 1; to: 8760; value: defaultTtlHours; editable: true; Layout.fillWidth: true }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: "NTP Server:"; Layout.preferredWidth: 120; font.pixelSize: 12 }
                            TextField { id: ntpServerField; text: ntpServer; Layout.fillWidth: true; placeholderText: "pool.ntp.org" }
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: "Output Dir:"; Layout.preferredWidth: 120; font.pixelSize: 12 }
                            TextField { id: outputDirField; text: outputDir; Layout.fillWidth: true; placeholderText: "Leave empty for same directory" }
                        }

                        Button {
                            text: "Save Settings"
                            Layout.fillWidth: true
                            height: 32
                            onClicked: {
                                pythonApi.savePreferences(
                                    defaultTtlSpin.value.toString(),
                                    ntpServerField.text,
                                    outputDirField.text
                                )
                            }
                        }
                    }
                }

                // Status
                GroupBox {
                    title: "Status"
                    Layout.fillWidth: true
                    Layout.fillHeight: true   // Make it expand vertically

                    Rectangle {
                        anchors.fill: parent
                        color: "#fafafa"
                        radius: 4
                        border.color: "#cccccc"

                        ScrollView {
                            anchors.fill: parent
                            anchors.margins: 8

                            Text {
                                text: statusText || "Ready"
                                font.pixelSize: 16    // Bigger text for readability
                                color: "#333"
                                wrapMode: Text.WordWrap
                                width: parent.width - 16 // Helps text wrap properly
                            }
                        }
                    }
                }
            }
        }
    }

    Component.onCompleted: {
        var now = new Date()
        yearSpin.value = now.getFullYear()
        monthSpin.value = now.getMonth() + 1
        daySpin.value = now.getDate()
        hourSpin.value = now.getHours()
        minuteSpin.value = now.getMinutes()
    }
}
