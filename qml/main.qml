import QtQuick 2.15
import QtQuick.Controls 2.15
import Qt.labs.platform 1.0

ApplicationWindow {
    id: win; width:800; height:820; visible:true
    title: "ImAged Viewer"

    Column { anchors.centerIn: parent; spacing:12

        Row { spacing:8
            Button { text:"Open Image";    onClicked: pythonApi.openImage() }
            Button { text:"Open .ttl";     onClicked: pythonApi.openTtl() }
            Button {
                text:"Default 1h TTL"
                enabled: pythonApi.imageUrl !== ""
                onClicked: pythonApi.convertToTtl()
            }
            Button {
                text:"Save as PNG"
                enabled: pythonApi.imageUrl !== ""
                onClicked: pythonApi.saveAsPng()
            }
            Button { text:"Preferences"; onClicked: prefPopup.open() }
        }

        GroupBox {
            title:"Custom Expiration"
            Column { spacing:8
                Row { spacing:6
                    Label { text:"Year:" }
                    ComboBox {
                        id: yearCombo
                        model: {
                            var ys=[]; var c=new Date().getFullYear();
                            for(var i=0;i<6;i++) ys.push(""+(c+i));
                            return ys;
                        }
                        currentIndex:0
                    }
                    Label { text:"Month:" }
                    ComboBox {
                        id: monthCombo
                        model: Array.from({length:12},(_,i)=>(i+1<10?"0":"")+(i+1))
                        currentIndex:new Date().getMonth()
                    }
                    Label { text:"Day:" }
                    ComboBox {
                        id: dayCombo
                        model: Array.from({length:31},(_,i)=>(i+1<10?"0":"")+(i+1))
                        currentIndex:new Date().getDate()-1
                    }
                }
                Row { spacing:6
                    Label { text:"Hour:" }
                    ComboBox {
                        id: hourCombo
                        model: Array.from({length:24},(_,i)=>(i<10?"0":"")+i)
                        currentIndex:new Date().getHours()
                    }
                    Label { text:"Minute:" }
                    ComboBox {
                        id: minuteCombo
                        model: Array.from({length:60},(_,i)=>(i<10?"0":"")+i)
                        currentIndex:new Date().getMinutes()
                    }
                }
                Button {
                    text:"Convert to .ttl (Custom)"
                    enabled: pythonApi.imageUrl !== ""
                    onClicked: pythonApi.convertToTtlCustom(
                        parseInt(yearCombo.currentText),
                        parseInt(monthCombo.currentText),
                        parseInt(dayCombo.currentText),
                        parseInt(hourCombo.currentText),
                        parseInt(minuteCombo.currentText)
                    )
                }
            }
        }

        DropArea {
            id: dropArea
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.8; height: 100
            onDropped: {
                drop.accepted = true
                if (drop.urls.length > 0) pythonApi.batchConvert(drop.urls[0])
            }
            Rectangle {
                anchors.fill: parent
                border.width: 2; border.color: "gray"; radius: 4
            }
            Text { anchors.centerIn: parent; text: "Drop a folder here to batch-convert images" }
        }

        ProgressBar {
            id: prog; from:0; to:pythonApi.total; value:pythonApi.progress
            width: parent.width * 0.8; height: 20
        }

        Image {
            id: displayedImage
            source: pythonApi.imageUrl
            fillMode: Image.PreserveAspectFit
            width: parent.width * 0.8; height: parent.height * 0.5
        }

        Text { text: pythonApi.statusText; font.pointSize:12 }
    }

    Popup {
        id: prefPopup
        modal: true; focus: true
        x: (win.width - width)/2
        y: (win.height - height)/2
        width: 400; height: 250

        contentItem: Column {
            anchors.fill: parent; anchors.margins:16; spacing:10

            Row { spacing:6
                Label { text:"Default TTL (h):" }
                TextField { id: ttlField; text: pythonApi.defaultTtlHours.toString() }
            }
            Row { spacing:6
                Label { text:"NTP Server:" }
                TextField { id: ntpField; text: pythonApi.ntpServer }
            }
            Row { spacing:6; height:30
                Label { text:"Output Dir:" }
                TextField { id: outField; text: pythonApi.outputDir; readOnly:true; width:200 }
                Button { text:"Browse"; onClicked: outDlg.open() }
            }
            FileDialog {
                id: outDlg
                title: "Choose Folder"
                fileMode: FileDialog.Directory
                onAccepted: outField.text = folder
            }

            Row {
                spacing:20
                anchors.horizontalCenter: parent.horizontalCenter
                Button {
                    text: "Save"
                    onClicked: {
                        pythonApi.savePreferences(
                            ttlField.text,
                            ntpField.text,
                            outField.text
                        )
                        prefPopup.close()
                    }
                }
                Button { text: "Cancel"; onClicked: prefPopup.close() }
            }
        }
    }
}
