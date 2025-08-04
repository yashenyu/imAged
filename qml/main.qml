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
    
    // Modern color scheme
    color: "#f5f5f5"
    
    // Properties for binding to Python backend
    property string imageUrl: pythonApi.imageUrl
    property string statusText: pythonApi.statusText
    property int defaultTtlHours: pythonApi.defaultTtlHours
    property string ntpServer: pythonApi.ntpServer
    property string outputDir: pythonApi.outputDir
    property int progress: pythonApi.progress
    property int total: pythonApi.total

    // File dialogs
    FolderDialog {
        id: folderDialog
        title: "Select Folder for Batch Conversion"
        onAccepted: {
            pythonApi.batchConvert(folder)
        }
    }

    // Main layout
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 20

        // Header
        Rectangle {
            Layout.fillWidth: true
            height: 60
            color: "#2196F3"
            radius: 8

            RowLayout {
                anchors.fill: parent
                anchors.margins: 15

                Text {
                    text: "ImAged"
                    font.pixelSize: 24
                    font.weight: Font.Bold
                    color: "white"
                }

                Item { Layout.fillWidth: true }

                Text {
                    text: "Time-Limited Image Encryption"
                    font.pixelSize: 14
                    color: "white"
                    opacity: 0.8
                }
            }
        }

        // Main content area
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 20

            // Left panel - Image display and controls
            ColumnLayout {
                Layout.preferredWidth: 500
                Layout.fillHeight: true
                spacing: 15

                // Image display area
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: "white"
                    radius: 8
                    border.color: "#e0e0e0"
                    border.width: 1

                    // Image
                    Image {
                        id: imageDisplay
                        anchors.fill: parent
                        anchors.margins: 10
                        source: imageUrl
                        fillMode: Image.PreserveAspectFit
                        cache: false

                        // Placeholder when no image
                        Rectangle {
                            anchors.fill: parent
                            color: "#fafafa"
                            visible: !imageDisplay.source || imageDisplay.source === ""
                            
                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 10

                                Text {
                                    text: "📷"
                                    font.pixelSize: 48
                                    horizontalAlignment: Text.AlignHCenter
                                }

                                Text {
                                    text: "No image loaded"
                                    font.pixelSize: 16
                                    color: "#666"
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
                    spacing: 10

                    Button {
                        text: "Open Image"
                        Layout.fillWidth: true
                        height: 40
                        background: Rectangle {
                            color: parent.pressed ? "#1976D2" : "#2196F3"
                            radius: 6
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: pythonApi.openImage()
                    }

                    Button {
                        text: "Open TTL"
                        Layout.fillWidth: true
                        height: 40
                        background: Rectangle {
                            color: parent.pressed ? "#388E3C" : "#4CAF50"
                            radius: 6
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: pythonApi.openTtl()
                    }

                    Button {
                        text: "Save PNG"
                        Layout.fillWidth: true
                        height: 40
                        background: Rectangle {
                            color: parent.pressed ? "#F57C00" : "#FF9800"
                            radius: 6
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: pythonApi.saveAsPng()
                    }
                }
            }

            // Right panel - Operations and settings
            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 15

                // TTL Conversion Section
                GroupBox {
                    title: "TTL Conversion"
                    Layout.fillWidth: true
                    font.pixelSize: 14
                    font.weight: Font.Bold

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 10

                        // Quick convert with default TTL
                        Button {
                            text: "Convert to TTL (Default: " + defaultTtlHours + "h)"
                            Layout.fillWidth: true
                            height: 45
                            background: Rectangle {
                                color: parent.pressed ? "#1976D2" : "#2196F3"
                                radius: 6
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                font.pixelSize: 14
                            }
                            onClicked: pythonApi.convertToTtl()
                        }

                        // Custom expiry section
                        Rectangle {
                            Layout.fillWidth: true
                            height: 120
                            color: "#f8f9fa"
                            radius: 6
                            border.color: "#e9ecef"
                            border.width: 1

                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 8

                                Text {
                                    text: "Custom Expiry:"
                                    font.pixelSize: 12
                                    font.weight: Font.Bold
                                    color: "#495057"
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 5

                                    SpinBox {
                                        id: yearSpin
                                        from: 2024
                                        to: 2030
                                        value: 2024
                                        editable: true
                                        Layout.fillWidth: true
                                    }

                                    Text { text: "-" }

                                    SpinBox {
                                        id: monthSpin
                                        from: 1
                                        to: 12
                                        value: 1
                                        editable: true
                                        Layout.fillWidth: true
                                    }

                                    Text { text: "-" }

                                    SpinBox {
                                        id: daySpin
                                        from: 1
                                        to: 31
                                        value: 1
                                        editable: true
                                        Layout.fillWidth: true
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 5

                                    SpinBox {
                                        id: hourSpin
                                        from: 0
                                        to: 23
                                        value: 12
                                        editable: true
                                        Layout.fillWidth: true
                                    }

                                    Text { text: ":" }

                                    SpinBox {
                                        id: minuteSpin
                                        from: 0
                                        to: 59
                                        value: 0
                                        editable: true
                                        Layout.fillWidth: true
                                    }

                                    Item { Layout.fillWidth: true }

                                    Button {
                                        text: "Convert"
                                        height: 30
                                        background: Rectangle {
                                            color: parent.pressed ? "#388E3C" : "#4CAF50"
                                            radius: 4
                                        }
                                        contentItem: Text {
                                            text: parent.text
                                            color: "white"
                                            horizontalAlignment: Text.AlignHCenter
                                            verticalAlignment: Text.AlignVCenter
                                            font.pixelSize: 12
                                        }
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

                        // Batch conversion
                        Button {
                            text: "Batch Convert Folder"
                            Layout.fillWidth: true
                            height: 40
                            background: Rectangle {
                                color: parent.pressed ? "#7B1FA2" : "#9C27B0"
                                radius: 6
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                            }
                            onClicked: folderDialog.open()
                        }

                        // Progress bar for batch operations
                        ProgressBar {
                            id: progressBar
                            Layout.fillWidth: true
                            height: 20
                            visible: total > 0
                            value: total > 0 ? progress / total : 0
                            
                            background: Rectangle {
                                color: "#e0e0e0"
                                radius: 10
                            }
                            
                            contentItem: Rectangle {
                                color: "#4CAF50"
                                radius: 10
                                width: progressBar.visualPosition * parent.width
                            }
                        }

                        Text {
                            text: total > 0 ? "Progress: " + progress + "/" + total : ""
                            font.pixelSize: 12
                            color: "#666"
                            visible: total > 0
                        }
                    }
                }

                // Settings Section
                GroupBox {
                    title: "Settings"
                    Layout.fillWidth: true
                    font.pixelSize: 14
                    font.weight: Font.Bold

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 10

                        // Default TTL
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "Default TTL (hours):"
                                Layout.preferredWidth: 120
                                font.pixelSize: 12
                            }
                            SpinBox {
                                id: defaultTtlSpin
                                from: 1
                                to: 8760  // 1 year
                                value: defaultTtlHours
                                editable: true
                                Layout.fillWidth: true
                            }
                        }

                        // NTP Server
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "NTP Server:"
                                Layout.preferredWidth: 120
                                font.pixelSize: 12
                            }
                            TextField {
                                id: ntpServerField
                                text: ntpServer
                                Layout.fillWidth: true
                                placeholderText: "pool.ntp.org"
                            }
                        }

                        // Output Directory
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "Output Dir:"
                                Layout.preferredWidth: 120
                                font.pixelSize: 12
                            }
                            TextField {
                                id: outputDirField
                                text: outputDir
                                Layout.fillWidth: true
                                placeholderText: "Leave empty for same directory"
                            }
                        }

                        // Save settings button
                        Button {
                            text: "Save Settings"
                            Layout.fillWidth: true
                            height: 35
                            background: Rectangle {
                                color: parent.pressed ? "#1976D2" : "#2196F3"
                                radius: 6
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                            }
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

                // Status Section
                GroupBox {
                    title: "Status"
                    Layout.fillWidth: true
                    font.pixelSize: 14
                    font.weight: Font.Bold

                    Rectangle {
                        anchors.fill: parent
                        color: "#f8f9fa"
                        radius: 6
                        border.color: "#e9ecef"
                        border.width: 1

                        ScrollView {
                            anchors.fill: parent
                            anchors.margins: 10

                            Text {
                                text: statusText || "Ready"
                                font.pixelSize: 12
                                color: "#495057"
                                wrapMode: Text.WordWrap
                                width: parent.width
                            }
                        }
                    }
                }
            }
        }
    }

    // Initialize with current date/time
    Component.onCompleted: {
        var now = new Date()
        yearSpin.value = now.getFullYear()
        monthSpin.value = now.getMonth() + 1
        daySpin.value = now.getDate()
        hourSpin.value = now.getHours()
        minuteSpin.value = now.getMinutes()
    }
}