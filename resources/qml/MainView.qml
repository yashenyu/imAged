import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: window
    width: 800
    height: 600
    visible: true
    title: "ImAged Viewer"

    // Material theme settings
    Material.theme: Material.Light
    Material.accent: Material.Blue

    header: ToolBar {
        RowLayout {
            anchors.fill: parent

            Button {
                text: "Open .ttl"
                onClicked: python.openFile()
            }

            Label {
                text: python.statusText
                Layout.alignment: Qt.AlignVCenter
                Layout.leftMargin: 20
                color: python.statusText.startsWith("Error") ? Material.color(Material.Red) : 
                       python.statusText.startsWith("Warning") ? Material.color(Material.Orange) : 
                       Material.foreground
            }
        }
    }

    Rectangle {
        anchors.fill: parent
        color: Material.background

        Image {
            id: displayImage
            anchors.fill: parent
            anchors.margins: 20
            fillMode: Image.PreserveAspectFit
            source: python.imageUrl
            
            // Placeholder when no image is loaded
            Rectangle {
                anchors.fill: parent
                visible: !displayImage.source
                color: Material.background
                border.color: Material.dividerColor
                border.width: 1
                
                Label {
                    anchors.centerIn: parent
                    text: "No image loaded"
                    color: Material.secondaryTextColor
                }
            }
        }
    }
}
