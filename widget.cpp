/* serial2net SSH - ComTester
 *
 * The Software "ComTester" is a handling tool for the diploma project
 * "serial2net" of hf-ict and should provide the possibility to users
 * testing there serial-ethernet converter installations.
 *
 * Copyright (C) 2016 Michael Ramstein 	<m.mislin@serial2net.ch>
 * Copyright (C) 2016 Michael Mislin 	<m.ramstein@serial2net.ch>
 * Copyright (C) 2016 Pascal Probst 	<p.probst@serial2net.ch>
 *
 * The software includes the libssh2 library >https://www.libssh2.org>
 * libssh2 is open source licensed under the 3-clause BSD License.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "widget.h"
#include "aboutdialog.h"
#include "version.h"

#include <QApplication>
#include <QByteArray>
#include <QComboBox>
#include <QDebug>
#include <QDesktopServices>
#include <QFont>
#include <QIcon>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QPixmap>
#include <QPushButton>
#include <QRadioButton>
#include <QSettings>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTcpSocket>
#include <QTextEdit>
#include <QThread>

#include <cmath>
#include <cstdlib>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QSpacerItem>
#include <QVBoxLayout>

Widget::Widget(QWidget *parent) : QWidget(parent) {
  Version *version = new Version();
  QString myVersion = version->getVersion();

  this->setWindowTitle("serial2net SSH - ComTester " + myVersion);
  this->setWindowIcon(QIcon(":/resource/ssh.png"));

  settingFilePath = "/settingsLibssh2.ini";
  strPath = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);

  settings = new QSettings(settingFilePath, QSettings::IniFormat);
  settings->setIniCodec("UTF-8");
  settings->setUserIniPath(strPath + settingFilePath);
  settings->setSystemIniPath(strPath + settingFilePath);
  qDebug() << "Scope QSetting: " << settings->scope();
  qDebug() << "File name QSetting" << settings->fileName();

  this->loadSettingStartUp();

  QFont fontTitel /*("", 8, QFont::Bold)*/;
  fontTitel.setBold(true);
  fontTitel.QFont::setUnderline(true);
  QFont fontNormal;
  fontNormal.setBold(false);
  fontNormal.QFont::setUnderline(false);

  widSocket = new QWidget();
  widSSH = new QWidget();
  widPort = new QWidget();
  widCMD = new QWidget();
  widBottomLine = new QWidget();

  tabWidget = new QTabWidget();
  tabWidget->addTab(widSocket, "TCP Socket");
  tabWidget->addTab(widSSH, "SSH Tunnel");
  tabWidget->addTab(widPort, "Port Scanner");

  tabIndex = this->tabWidget->currentIndex();
  qDebug() << "tabIndex: " << tabIndex;

  btnConnectTunnel = new QPushButton("Connect Tunnel");
  btnConnectTunnel->setToolTip(
      "Start connecting process\r\n"
      "for do SSH-Tunnel");
  btnConnectTunnel->setCheckable(true);
  btnConnectSocket = new QPushButton("Connect Socket");
  btnConnectSocket->setToolTip(
      "Start connecting process\r\n"
      "for do TCP-Connection");
  btnConnectSocket->setCheckable(true);
  btnPortScanner = new QPushButton("Start Scan");
  btnPortScanner->setToolTip(
      "Start connecting process\r\n"
      "for scanning ports within the\r\n"
      "set range");
  btnPortScanner->setCheckable(true);
  btnSendCommand = new QPushButton("Send");
  btnSendCommand->setToolTip("Submit the command");
  btnSendCommand->setFixedWidth(100);
  btnSave = new QPushButton("Save");
  btnSave->setToolTip("Save done settings inside fields");
  btnSave->setFixedWidth(100);
  btnLoad = new QPushButton("Load");
  btnLoad->setToolTip("Load last saved settings");
  btnLoad->setFixedWidth(100);
  btnExit = new QPushButton("Quit");
  btnExit->setToolTip(
      "Quit application without\r\n"
      "saving settings of fields");
  btnExit->setFixedWidth(100);
  btnDeleteTxtEdit = new QPushButton("Delete Log");

  btnInfoSocket = new QPushButton();
  btnInfoTunnel = new QPushButton();
  btnInfoScanner = new QPushButton();
  btnInfoCommand = new QPushButton();
  btnInfoLicense = new QPushButton();
  btnInfoEncryption = new QPushButton();
  btnBugReport = new QPushButton();
  btnHelp = new QPushButton();
  btnAbout = new QPushButton();

  btnInfoSocket->setIcon(QIcon(":/resource/infoSign.png"));
  btnInfoTunnel->setIcon(QIcon(":/resource/infoSign.png"));
  btnInfoScanner->setIcon(QIcon(":/resource/infoSign.png"));
  btnInfoCommand->setIcon(QIcon(":/resource/infoSign.png"));
  btnInfoLicense->setIcon(QIcon(":/resource/copyrightSign.png"));
  btnInfoEncryption->setIcon(QIcon(":/resource/encryptionSign.png"));
  btnBugReport->setIcon(QIcon(":/resource/bugSign.png"));
  btnHelp->setIcon(QIcon(":/resource/helpSign.png"));
  btnAbout->setIcon(QIcon(":/resource/aboutSign.png"));

  QString styleIconButton =
      "color: transparent;"
      "border-color: transparent;"
      "border-style: outset;"
      "background-color: transparent;"
      "selection-color: transparent;"
      "selection-background-color: transparent;"
      "border-width: 0px;";

  btnInfoSocket->setStyleSheet(styleIconButton);
  btnInfoTunnel->setStyleSheet(styleIconButton);
  btnInfoScanner->setStyleSheet(styleIconButton);
  btnInfoCommand->setStyleSheet(styleIconButton);
  btnInfoLicense->setStyleSheet(styleIconButton);
  btnInfoEncryption->setStyleSheet(styleIconButton);
  btnBugReport->setStyleSheet(styleIconButton);
  btnHelp->setStyleSheet(styleIconButton);
  btnAbout->setStyleSheet(styleIconButton);

  rbtAscii = new QRadioButton("ASCII");
  rbtAscii->setChecked(convertStringToBool(CommandIsAscii));
  rbtHex = new QRadioButton("Hex");
  rbtHex->setChecked(convertStringToBool(CommandIsHex));
  if (!rbtAscii->isChecked() && !rbtHex->isChecked()) {
    rbtAscii->setChecked(true);
  }

  cboConvertHexTo = new QComboBox();
  cboConvertHexTo->addItem("");
  cboConvertHexTo->addItem("Float");
  cboConvertHexTo->addItem("Integer");
  cboConvertHexTo->addItem("String");
  cboConvertHexTo->setEnabled(false);
  cboConvertHexTo->setCurrentText(CommandConvertHexTo);

  lblLicense = new QLabel("License & Copyright(C)");
  lblInfoEncryption = new QLabel("Encryption");
  lblBugReport = new QLabel("Bug Reporting");
  lblHelp = new QLabel("Help");
  lblAbout = new QLabel("About");

  lblSshTitel = new QLabel("SSH settings");
  lblSshTitel->setFont(fontTitel);
  lblSshHost = new QLabel("SSH host/IP:");
  lblSshPort = new QLabel("SSH port:");
  lblSshUser = new QLabel("SSH user:");
  lblSshPassword = new QLabel("SSH password:");

  lblTunnelTitel = new QLabel("Tunnel settings");
  lblTunnelTitel->setFont(fontTitel);
  lblTunnelHost = new QLabel("Tunnel host:");
  lblTunnelClient = new QLabel("Client host:");
  lblTunnelClientPort = new QLabel("Tunnel port:");
  lblTunnelServerPort = new QLabel("Tunnel port:");
  lblTunnelTimeout = new QLabel("Timeout [ms]:");

  lblSocketTitel = new QLabel("Socket settings");
  lblSocketTitel->setFont(fontTitel);
  lblSocketHost = new QLabel("Socket host:");
  lblSocketPort = new QLabel("Socket port:");
  lblSocketTimeout = new QLabel("Timeout [ms]:");

  lblCommandTitel = new QLabel("Command");
  lblCommandTitel->setFont(fontTitel);
  lblSignCode = new QLabel("Sign code:");
  lblConvertHexTo = new QLabel("Convert HEX to");
  lblNoBytesFromRight = new QLabel("Bytes from right:");
  lblCommand = new QLabel("Send command:");
  lblCommandStartSign = new QLabel("Start sign");
  lblCommandStopSign = new QLabel("Stop sign");
  lblCommandDelimiter = new QLabel("Delimiter");
  lblCommandTimeout = new QLabel("Timeout [ms]:");

  lblScannerTitel = new QLabel("Port Scanning");
  lblScannerTitel->setFont(fontTitel);
  lblScannerHost = new QLabel("Host:");
  lblScannerPortFrom = new QLabel("Port from:");
  lblScannerPortTo = new QLabel("Port to:");
  lblScannerTimeout = new QLabel("Timeout [ms]:");
  lblScannerRemarks = new QLabel(
      "Remarks:\r\n"
      "The port scanner tool is not thought for\r\n"
      "do wide range scanning.\r\n"
      "The Software will be blocked during\r\n"
      "scanning take place!");

  QIntValidator *valIntUnsigned16 = new QIntValidator(1, 65535);

  letSshHost = new QLineEdit(SshHost);
  letSshHost->setToolTip("Domain-Name or IPv4-Address of target interface");
  letSshHost->setPlaceholderText("serial2net.dyndns.org");
  letSshPort = new QLineEdit(SshPort);
  letSshPort->setToolTip("Port number within the range 1 to 65'535");
  letSshPort->setValidator(valIntUnsigned16);
  letSshPort->setPlaceholderText("22");
  letSshUser = new QLineEdit(SshUser);
  letSshUser->setToolTip("User name to sign on at SSH-Login");
  letSshUser->setPlaceholderText("myLogin");
  letSshPassword = new QLineEdit(SshPassword);
  letSshPassword->setToolTip("Password to sign on at SSH-Login");
  letSshPassword->setPlaceholderText("myPassword");
  letSshPassword->setEchoMode(QLineEdit::Password);
  letTunnelHost = new QLineEdit(TunnelServer);
  letTunnelHost->setToolTip(
      "Domain-Name \"localhost\" or IPv4-Adress\r\n"
      "within the range 127.0.0.1 to 127.255.255.254");
  letTunnelHost->setPlaceholderText("localhost");
  letTunnelClient = new QLineEdit(TunnelClient);
  letTunnelClient->setToolTip(
      "Domain-Name \"localhost\" or IPv4-Adress\r\n"
      "within the range 127.0.0.1 to 127.255.255.254");
  letTunnelClient->setPlaceholderText("localhost");
  letTunnelClientPort = new QLineEdit(TunnelClientPort);
  letTunnelClientPort->setToolTip("Port number within the range 1 to 65'535");
  letTunnelClientPort->setValidator(valIntUnsigned16);
  letTunnelClientPort->setPlaceholderText("10002");
  letTunnelServerPort = new QLineEdit(TunnelServerPort);
  letTunnelServerPort->setToolTip("Port number within the range 1 to 65'535");
  letTunnelServerPort->setValidator(valIntUnsigned16);
  letTunnelServerPort->setPlaceholderText("10002");
  letTunnelTimeout = new QLineEdit(TunnelTimeout);
  letTunnelTimeout->setToolTip(
      "Time in millisecond within the range 1 to 65'535");
  letTunnelTimeout->setValidator(valIntUnsigned16);
  letTunnelTimeout->setPlaceholderText("1000");

  letSocketHost = new QLineEdit(SocketHost);
  letSocketHost->setToolTip("Domain-Name or IPv4-Address of target interface");
  letSocketHost->setPlaceholderText("serial2net.dyndns.org");
  letSocketPort = new QLineEdit(SocketPort);
  letSocketPort->setToolTip("Port number within the range 1 to 65'535");
  letSocketPort->setValidator(valIntUnsigned16);
  letSocketPort->setPlaceholderText("10002");
  letSocketTimeout = new QLineEdit(SocketTimeout);
  letSocketTimeout->setToolTip(
      "Time in millisecond within the range 1 to 65'535");
  letSocketTimeout->setValidator(valIntUnsigned16);
  letSocketTimeout->setPlaceholderText("2000");

  letCommand = new QLineEdit(Command);
  letCommand->setToolTip(
      "Command according technical manual\r\n"
      "of target interface\r\n\r\n"
      "if set on ASCII put in e.g. PA990\r\n"
      "if set on HEX put in e.g. 6F 03 01 08 00 02 4C BB\r\n");
  letCommand->setPlaceholderText("PA1");
  letNoBytesFromRight = new QLineEdit(CommandBytesFromRight);
  letNoBytesFromRight->setFixedWidth(30);
  letNoBytesFromRight->setPlaceholderText("4");
  letNoBytesFromRight->setValidator(valIntUnsigned16);
  letNoBytesFromRight->setToolTip(
      "Define the amount of bytes are used to\r\n"
      "convertto float, integer or string");
  letCommandStartSign = new QLineEdit(CommandStartSign);
  letCommandStartSign->setToolTip(
      "Start sign for the serial\r\n"
      "communication according technical manual\r\n"
      "of target interface");
  letCommandStartSign->setPlaceholderText("@");
  letCommandStartSign->setFixedWidth(30);
  letCommandStopSign = new QLineEdit(CommandStopSign);
  letCommandStopSign->setToolTip(
      "Stop sign for the serial communication\r\n"
      "according technical manual of target\r\n"
      "interface.\r\n"
      "\r\n"
      "Follwoing control signs are implemented\r\n"
      "as follow:"
      "\\a as <BEL>\t(bel)\r\n"
      "\\b as <BS>\t(backspace)\r\n"
      "\\t as <HT>\t(horizontal tab)\r\n"
      "\\n as <LF>\t(new line) \r\n"
      "\\v as <VT>\t(vertical tab)\r\n"
      "\\f as <FF>\t(form feed)\r\n"
      "\\r as <CR>\t(carriage return)\r\n"
      "\r\n"
      "Example: use \"<CR>\" instead of \"\\n\"");
  letCommandStopSign->setPlaceholderText("<CR><LF>");
  letCommandStopSign->setFixedWidth(70);
  letCommandDelimiter = new QLineEdit(CommandDelimiter);
  letCommandDelimiter->setToolTip(
      "Delimiter sign for the serial\r\n"
      "communication according technical manual\r\n"
      "of target interface");
  letCommandDelimiter->setPlaceholderText(".");
  letCommandDelimiter->setFixedWidth(70);
  letCommandTimeout = new QLineEdit(CommandTimeout);
  letCommandTimeout->setToolTip(
      "Time in millisecond within the range 1 to 65'535");
  letCommandTimeout->setValidator(valIntUnsigned16);
  letCommandTimeout->setPlaceholderText("200");
  letCommandTimeout->setFixedWidth(50);

  letScannerHost = new QLineEdit(ScannerHost);
  letScannerHost->setToolTip("Domain-Name or IPv4-Address of target interface");
  letScannerHost->setPlaceholderText("serial2net.dyndns.org");
  letScannerPortFrom = new QLineEdit(ScannerPortFrom);
  letScannerPortFrom->setToolTip("Port number within the range 1 to 65'535");
  letScannerPortFrom->setValidator(valIntUnsigned16);
  letScannerPortFrom->setPlaceholderText("0");
  letScannerPortTo = new QLineEdit(ScannerPortTo);
  letScannerPortTo->setToolTip("Port number within the range 1 to 65'535");
  letScannerPortTo->setValidator(valIntUnsigned16);
  letScannerPortTo->setPlaceholderText("65535");
  letScannerTimeout = new QLineEdit(ScannerTimeout);
  letScannerTimeout->setToolTip(
      "Time in millisecond within the range 1 to 65'535");
  letScannerTimeout->setValidator(valIntUnsigned16);
  letScannerTimeout->setPlaceholderText("100");

  tetTunnelQuery = new QTextEdit();
  tetTunnelQuery->setMinimumWidth(290);

  lblPictureSchematic = new QLabel();
  QPixmap pxpPictureSocket(":/resource/picSocket.png");
  lblPictureSchematic->setPixmap(pxpPictureSocket);

  QHBoxLayout *hblMenuLine = new QHBoxLayout();
  QHBoxLayout *hblPixmap = new QHBoxLayout();
  QHBoxLayout *hblTotal = new QHBoxLayout();
  QVBoxLayout *vblLeft = new QVBoxLayout();
  QVBoxLayout *vblRight = new QVBoxLayout();
  QGridLayout *grlData = new QGridLayout();
  QGridLayout *grlSocket = new QGridLayout();
  QGridLayout *grlSSH = new QGridLayout();
  QGridLayout *grlPort = new QGridLayout();
  QGridLayout *grlBottomLine = new QGridLayout();

  QSpacerItem *spacer0 = new QSpacerItem(390, 1);  // int W, int H
  QSpacerItem *spacer1 = new QSpacerItem(500, 110);
  // QSpacerItem *spacer2 = new QSpacerItem(1, 10);
  QSpacerItem *spacer3 = new QSpacerItem(310, 30);
  QSpacerItem *spacer4 = new QSpacerItem(578, 1);
  QSpacerItem *spacer5 = new QSpacerItem(1, 21);
  QSpacerItem *spacer6 = new QSpacerItem(1, 9);
  QSpacerItem *spacer7 = new QSpacerItem(20, 1);
  QSpacerItem *spacer8 = new QSpacerItem(20, 1);
  QSpacerItem *spacer9 = new QSpacerItem(20, 1);
  QSpacerItem *spacer10 = new QSpacerItem(20, 1);

  hblMenuLine->addWidget(btnInfoLicense);
  hblMenuLine->addWidget(lblLicense);
  hblMenuLine->addItem(spacer7);
  hblMenuLine->addWidget(btnInfoEncryption);
  hblMenuLine->addWidget(lblInfoEncryption);
  hblMenuLine->addItem(spacer8);
  hblMenuLine->addWidget(btnBugReport);
  hblMenuLine->addWidget(lblBugReport);
  hblMenuLine->addItem(spacer9);
  hblMenuLine->addWidget(btnHelp);
  hblMenuLine->addWidget(lblHelp);
  hblMenuLine->addItem(spacer10);
  hblMenuLine->addWidget(btnAbout);
  hblMenuLine->addWidget(lblAbout);
  hblMenuLine->addItem(spacer0);

  hblPixmap->addWidget(lblPictureSchematic);

  grlSocket->addWidget(btnInfoSocket, 0, 0);  // row, column
  grlSocket->addWidget(lblSocketTitel, 0, 1);
  grlSocket->addWidget(lblSocketHost, 1, 4);
  grlSocket->addWidget(letSocketHost, 1, 5);
  grlSocket->addWidget(lblSocketPort, 2, 4);
  grlSocket->addWidget(letSocketPort, 2, 5);
  grlSocket->addWidget(lblSocketTimeout, 3, 4);
  grlSocket->addWidget(letSocketTimeout, 3, 5);
  grlSocket->addWidget(btnConnectSocket, 4, 5);
  grlSocket->addItem(spacer1, 5, 2);
  widSocket->setLayout(grlSocket);

  grlSSH->addWidget(btnInfoTunnel, 0, 0);  // row, column
  grlSSH->addWidget(lblSshTitel, 0, 1);
  grlSSH->addWidget(lblSshHost, 1, 3);
  grlSSH->addWidget(letSshHost, 1, 4);
  grlSSH->addWidget(lblSshPort, 2, 3);
  grlSSH->addWidget(letSshPort, 2, 4);
  grlSSH->addWidget(lblSshUser, 3, 3);
  grlSSH->addWidget(letSshUser, 3, 4);
  grlSSH->addWidget(lblSshPassword, 4, 3);
  grlSSH->addWidget(letSshPassword, 4, 4);
  grlSSH->addWidget(lblTunnelTitel, 5, 1);
  grlSSH->addWidget(lblTunnelClient, 6, 1);
  grlSSH->addWidget(letTunnelClient, 6, 2); 
  grlSSH->addWidget(lblTunnelTimeout, 6, 3);
  grlSSH->addWidget(letTunnelTimeout, 6, 4);
  grlSSH->addWidget(lblTunnelHost, 6, 5);
  grlSSH->addWidget(letTunnelHost, 6, 6); 
  grlSSH->addWidget(lblTunnelClientPort, 7, 1);
  grlSSH->addWidget(letTunnelClientPort, 7, 2);
  grlSSH->addWidget(lblTunnelServerPort, 7, 5);
  grlSSH->addWidget(letTunnelServerPort, 7, 6);
  grlSSH->addWidget(btnConnectTunnel, 8, 6);
  widSSH->setLayout(grlSSH);

  grlData->addWidget(btnInfoCommand, 0, 0);  // row, column
  grlData->addWidget(lblCommandTitel, 0, 1);
  grlData->addWidget(lblSignCode, 1, 1);
  grlData->addWidget(rbtAscii, 1, 2);
  grlData->addWidget(rbtHex, 2, 2);
  grlData->addWidget(lblCommand, 1, 3);
  grlData->addWidget(lblConvertHexTo, 2, 3);
  grlData->addWidget(letCommand, 1, 4);
  grlData->addWidget(cboConvertHexTo, 2, 4);
  grlData->addWidget(lblCommandStartSign, 1, 5);
  grlData->addWidget(lblNoBytesFromRight, 2, 5);
  grlData->addWidget(letCommandStartSign, 1, 6);
  grlData->addWidget(letNoBytesFromRight, 2, 6);
  grlData->addWidget(lblCommandStopSign, 1, 7);
  grlData->addWidget(letCommandStopSign, 1, 8);
  // grlData -> addWidget(lblCommandDelimiter, 1, 9);
  // grlData -> addWidget(letCommandDelimiter, 1, 10);
  grlData->addWidget(lblCommandTimeout, 1, 11);
  grlData->addWidget(letCommandTimeout, 1, 12);
  grlData->addWidget(btnSendCommand, 1, 13);
  widCMD->setLayout(grlData);

  grlPort->addWidget(btnInfoScanner, 0, 0);  // row, column
  grlPort->addWidget(lblScannerTitel, 0, 1);
  grlPort->addWidget(lblScannerHost, 1, 1);
  grlPort->addWidget(letScannerHost, 1, 2);
  grlPort->addWidget(lblScannerPortFrom, 2, 1);
  grlPort->addWidget(letScannerPortFrom, 2, 2);
  grlPort->addWidget(lblScannerPortTo, 2, 3);
  grlPort->addWidget(letScannerPortTo, 2, 4);
  grlPort->addWidget(lblScannerTimeout, 3, 1);
  grlPort->addWidget(letScannerTimeout, 3, 2);
  grlPort->addWidget(btnPortScanner, 4, 4);
  grlPort->addWidget(lblScannerRemarks, 5, 4);
  grlPort->addItem(spacer3, 6, 6);  // spacer to right & bottom
  widPort->setLayout(grlPort);

  grlBottomLine->addWidget(btnSave, 0, 0);  // row, column
  grlBottomLine->addWidget(btnLoad, 0, 1);
  grlBottomLine->addWidget(btnExit, 0, 5);
  grlBottomLine->addItem(spacer4, 0, 4);
  widBottomLine->setLayout(grlBottomLine);

  vblLeft->addLayout(hblMenuLine);
  vblLeft->addLayout(hblPixmap);
  vblLeft->addWidget(tabWidget);
  vblLeft->addWidget(widCMD);
  vblLeft->addWidget(widBottomLine);

  vblRight->addItem(spacer5);
  vblRight->addWidget(tetTunnelQuery);
  vblRight->addWidget(btnDeleteTxtEdit);
  vblRight->addItem(spacer6);

  hblTotal->addLayout(vblLeft);
  hblTotal->addLayout(vblRight);

  this->setLayout(hblTotal);
  this->show();

  connect(btnConnectTunnel, SIGNAL(clicked(bool)), this,
          SLOT(btnConnectTunnelClicked(bool)));
  connect(btnConnectSocket, SIGNAL(clicked(bool)), this,
          SLOT(btnConnectSocketClicked(bool)));
  connect(btnPortScanner, SIGNAL(clicked(bool)), this,
          SLOT(btnSendPortScannerClicked(bool)));
  connect(btnSendCommand, SIGNAL(clicked(bool)), this,
          SLOT(btnSendCommandClicked(bool)));
  connect(btnSave, SIGNAL(clicked(bool)), this, SLOT(btnSaveClicked(bool)));
  connect(btnLoad, SIGNAL(clicked(bool)), this, SLOT(btnLoadClicked(bool)));
  connect(btnExit, SIGNAL(clicked(bool)), this, SLOT(btnExitClicked(bool)));
  connect(btnInfoSocket, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoSocketClicked(bool)));
  connect(btnInfoTunnel, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoTunnelClicked(bool)));
  connect(btnInfoScanner, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoScannerClicked(bool)));
  connect(btnInfoCommand, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoCommandClicked(bool)));
  connect(btnInfoLicense, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoLicenseClicked(bool)));
  connect(btnDeleteTxtEdit, SIGNAL(clicked(bool)), this,
          SLOT(btnDeleteTxtEditClicked(bool)));
  connect(btnInfoEncryption, SIGNAL(clicked(bool)), this,
          SLOT(btnInfoEncryptionClicked(bool)));
  connect(btnBugReport, SIGNAL(clicked(bool)), this,
          SLOT(btnBugReportClicked(bool)));
  connect(btnHelp, SIGNAL(clicked(bool)), this, SLOT(btnHelpClicked(bool)));
  connect(btnAbout, SIGNAL(clicked(bool)), this, SLOT(btnAboutClicked(bool)));

  connect(tabWidget, SIGNAL(currentChanged(int)), this, SLOT(tabChanged(int)));
  connect(letCommand, SIGNAL(returnPressed()), this,
          SLOT(letCommandReturnPressed()));
  connect(rbtAscii, SIGNAL(clicked(bool)), this, SLOT(rbtAsciiClicked(bool)));
  connect(rbtHex, SIGNAL(clicked(bool)), this, SLOT(rbtHexClicked(bool)));
  connect(cboConvertHexTo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(cboIndexChanged(int)));

  varTimeoutTunnel = letTunnelTimeout->text().toInt();
  varTimeoutSocket = letSocketTimeout->text().toInt();
  varTimeoutCommand = letCommandTimeout->text().toInt();
  varTimeoutScanner = letScannerTimeout->text().toInt();

  btnSendCommand->setEnabled(false);
  this->setLineEditCommandDisable();

  myTunnel = new sshtunnel(varTimeoutTunnel, varTimeoutCommand);
  mySocket = new tcpsocket(varTimeoutSocket, varTimeoutCommand);

  myTextInterface = new TextInterface();
}

QString Widget::addTextToTextField(QString additionalText) {
  additionalText = convertCrtlSignToWildcard(additionalText);

  QString tmp = tetTunnelQuery->toPlainText();
  tmp = additionalText + "\r\n" + tmp;
  tetTunnelQuery->setText("");
  tetTunnelQuery->setText(tmp);
  return tmp;
}

QString Widget::convertWildcardToCrtlSign(QString data) {
  qDebug() << "showCrtlSign";

  data.replace("<BEL>", "\a");  // bel
  data.replace("<BS>", "\b");   // backspace
  data.replace("<HT>", "\t");   // horizontal tab
  data.replace("<LF>", "\n");   // new line
  data.replace("<VT>", "\v");   // vertical tab
  data.replace("<FF>", "\f");   // form feed
  data.replace("<CR>", "\r");   // carriage return

  return data;
}

QString Widget::convertCrtlSignToWildcard(QString data) {
  qDebug() << "convertCrtlSignToWildcard";

  data.replace("\a", "<BEL>");  // bel
  data.replace("\b", "<BS>");   // backspace
  data.replace("\t", "<HT>");   // horizontal tab
  data.replace("\n", "<LF>");   // new line
  data.replace("\v", "<VT>");   // vertical tab
  data.replace("\f", "<FF>");   // form feed
  data.replace("\r", "<CR>");   // carriage return

  return data;
}

void Widget::setLineEditTunnelDisable() {
  btnConnectTunnel->setEnabled(false);
  letSshHost->setEnabled(false);
  letSshPort->setEnabled(false);
  letSshUser->setEnabled(false);
  letSshPassword->setEnabled(false);
  letTunnelHost->setEnabled(false);
  letTunnelClientPort->setEnabled(false);
  letTunnelServerPort->setEnabled(false);
  letTunnelClient->setEnabled(false);
  letTunnelTimeout->setEnabled(false);
}

void Widget::setLineEditTunnelEnable() {
  btnConnectTunnel->setEnabled(true);
  letSshHost->setEnabled(true);
  letSshPort->setEnabled(true);
  letSshUser->setEnabled(true);
  letSshPassword->setEnabled(true);
  letTunnelHost->setEnabled(true);
  letTunnelClientPort->setEnabled(true);
  letTunnelServerPort->setEnabled(true);
  letTunnelClient->setEnabled(true);
  letTunnelTimeout->setEnabled(true);
}

void Widget::setLineEditSocketDisable() {
  btnConnectSocket->setEnabled(false);
  letSocketHost->setEnabled(false);
  letSocketPort->setEnabled(false);
  letSocketTimeout->setEnabled(false);
}

void Widget::setLineEditSocketEnable() {
  btnConnectSocket->setEnabled(true);
  letSocketHost->setEnabled(true);
  letSocketPort->setEnabled(true);
  letSocketTimeout->setEnabled(true);
}

void Widget::setLineEditScanPortDisable() {
  btnPortScanner->setEnabled(false);
  letScannerHost->setEnabled(false);
  letScannerPortFrom->setEnabled(false);
  letScannerPortTo->setEnabled(false);
  letScannerTimeout->setEnabled(false);
}

void Widget::setLineEditScanPortEnable() {
  btnPortScanner->setEnabled(true);
  letScannerHost->setEnabled(true);
  letScannerPortFrom->setEnabled(true);
  letScannerPortTo->setEnabled(true);
  letScannerTimeout->setEnabled(true);
}

void Widget::setLineEditCommandDisable() {
  btnSendCommand->setEnabled(false);
  letCommand->setEnabled(false);
  letCommandTimeout->setEnabled(false);
  letCommandStartSign->setEnabled(false);
  letCommandStopSign->setEnabled(false);
  letCommandDelimiter->setEnabled(false);
  cboConvertHexTo->setEnabled(false);
  letNoBytesFromRight->setEnabled(false);
  rbtAscii->setEnabled(false);
  rbtHex->setEnabled(false);
}

void Widget::setLineEditCommandEnable() {
  btnSendCommand->setEnabled(true);
  letCommand->setEnabled(true);
  letCommandTimeout->setEnabled(true);
  letCommandStartSign->setEnabled(true);
  letCommandStopSign->setEnabled(true);
  letCommandDelimiter->setEnabled(true);
  cboConvertHexTo->setEnabled(true);
  letNoBytesFromRight->setEnabled(true);
  rbtAscii->setEnabled(true);
  rbtHex->setEnabled(true);
}

void Widget::setBottomButtonDisable() {
  btnSave->setEnabled(false);
  btnLoad->setEnabled(false);
  btnExit->setEnabled(false);
}

void Widget::setBottomButtonEnable() {
  btnSave->setEnabled(true);
  btnLoad->setEnabled(true);
  btnExit->setEnabled(true);
}

void Widget::btnConnectTunnelClicked(bool click) {
  qDebug() << btnConnectTunnel;

  varTimeoutTunnel = letTunnelTimeout->text().toInt();
  qDebug() << "varTimeoutTunnel" << varTimeoutTunnel;

  intTunnelState = -47;  // Start value

  if (click) {
    this->setLineEditTunnelDisable();
    this->setLineEditSocketDisable();
    this->setLineEditScanPortDisable();
    this->setLineEditCommandEnable();
    this->setBottomButtonDisable();

    btnConnectTunnel->setEnabled(true);
    btnConnectSocket->setEnabled(false);
    btnPortScanner->setEnabled(false);

    btnConnectTunnel->setText("Disconnect Tunnel");
    varSshPort = letSshPort->text().toInt();
    baSshHost = letSshHost->text().toLatin1();
    varSshHost = baSshHost.data();
    baSshUser = letSshUser->text().toLatin1();
    varSshUser = baSshUser.data();
    baSshPassword = letSshPassword->text().toLatin1();
    varSshPassword = baSshPassword.data();
    baTunnelServer = letTunnelHost->text().toLatin1();
    varTunnelServer = baTunnelServer.data();
    varTunnelClientPort = letTunnelClientPort->text().toInt();
    varTunnelServerPort = letTunnelServerPort->text().toInt();
    baTunnelClient = letTunnelClient->text().toLatin1();
    varTunnelClient = baTunnelClient.data();

    myTunnel->getTunnelData(varSshPort, varSshHost,
                            varSshUser, varSshPassword,
                            varTunnelClient, varTunnelClientPort,
                            varTunnelServer, varTunnelServerPort);

    strState = addTextToTextField("Connecting SSH-Tunnel...");

    qDebug() << true;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    intTunnelState =
        myTunnel->doConnectDisconnectTunnel(click, varTimeoutTunnel);
    qDebug() << "doConnectDisconnectTunnel" << intTunnelState;

    switch (intTunnelState) {
      case -8:
        strState = "Not connected! Code: -8";
        break;

      case -7:
        strState = "Not connected! Code: -7";
        break;

      case -6:
        strState = "Not connected! Code: -6";
        break;

      case -5:
        strState = "Connected! Code: -5";
        break;

      case -4:
        strState = "Not connected! Code: -4";
        break;

      case -3:
        strState = "Not connected! Code: -3";
        break;

      case -2:
        strState = "Not connected! Code: -2";
        break;

      case -1:
        strState = "Not connected! Code: -1";
        break;

      case 0:
        strState = "Connected! Code: 0";
        break;
    }

    QApplication::setOverrideCursor(Qt::ArrowCursor);

    if (intTunnelState < 0) {
      btnConnectTunnel->setChecked(false);
      btnConnectTunnel->setText("Connect Tunnel");

      this->setLineEditTunnelEnable();
      this->setLineEditCommandDisable();
      this->setLineEditSocketEnable();
      this->setLineEditScanPortEnable();
      this->setBottomButtonEnable();
    }
  }

  if (!click) {
    this->setLineEditTunnelEnable();
    this->setLineEditSocketEnable();
    this->setLineEditScanPortEnable();
    this->setBottomButtonEnable();

    btnConnectSocket->setEnabled(true);
    btnPortScanner->setEnabled(true);
    letCommandTimeout->setEnabled(true);

    intTunnelState = -47;  // Start value

    btnConnectTunnel->setText("Connect Tunnel");
    addTextToTextField("Disconnecting SSH-Tunnel...");

    this->setLineEditCommandDisable();

    qDebug() << false;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    intTunnelState =
        myTunnel->doConnectDisconnectTunnel(click, varTimeoutTunnel);
    qDebug() << "doConnectDisconnectTunnel" << intTunnelState;
    qDebug() << "check out LIBSSH2_ERROR_EAGAIN no. " << intTunnelState;
    qDebug()
        << "for reference check out LIBSSH2_ERROR_NONE inside libssh2.h file";
    QApplication::setOverrideCursor(Qt::ArrowCursor);

    if (intTunnelState < 0) {
      intTunnelState = -1;
    }

    switch (intTunnelState) {
      case -1:
        strState = "Problem disconnecting! Code: -1";
        break;

      case 0:
        strState = "Disconnected! Code: 0";
        break;
    }

    qDebug() << "Sleep 1s. to prevent the user to reconnect directly (crash if "
                "not completly disconnected)";
    QThread::sleep(1);
  }

  addTextToTextField(strState);

  if (strState == "Disconnected! Code: 0") {
    addTextToTextField("");
  }
}

void Widget::btnConnectSocketClicked(bool click) {
  qDebug() << btnConnectSocket;

  varTimeoutSocket = letSocketTimeout->text().toInt();
  qDebug() << "varTimeoutTunnel" << varTimeoutSocket;

  btnConnectSocket->setEnabled(false);
  btnConnectTunnel->setEnabled(false);
  btnPortScanner->setEnabled(false);

  QApplication::setOverrideCursor(Qt::WaitCursor);

  if (click) {
    this->setLineEditSocketDisable();
    this->setLineEditTunnelDisable();
    this->setLineEditScanPortDisable();
    this->setLineEditCommandEnable();
    this->setBottomButtonDisable();

    btnConnectSocket->setEnabled(true);

    intSocketState = -3;  // Start value

    btnConnectSocket->setEnabled(true);

    btnConnectSocket->setText("Disconnect TCP-Socket");

    intSocketState = mySocket->doConnect(
        letSocketHost->text(), letSocketPort->text().toInt(), varTimeoutSocket);

    if (intSocketState) {
      intTunnelState = 0;  // no fault
      addTextToTextField("Connected TCP-Socket! Code: " +
                         QString::number(intTunnelState));
    }

    if (!intSocketState) {
      intTunnelState = -1;  // any fault
      addTextToTextField("Problem connecting TCP-Socket! Code: " +
                         QString::number(intTunnelState));

      btnConnectSocket->setChecked(false);
      btnConnectSocket->setText("Connect Socket");
      this->setLineEditSocketEnable();
      this->setLineEditTunnelEnable();
      this->setLineEditScanPortEnable();
      this->setLineEditCommandDisable();
      this->setBottomButtonEnable();
    }
  }

  if (!click) {
    this->setLineEditSocketEnable();
    this->setLineEditTunnelEnable();
    this->setLineEditScanPortEnable();
    this->setLineEditCommandDisable();
    this->setBottomButtonEnable();

    btnConnectTunnel->setEnabled(true);
    btnPortScanner->setEnabled(true);

    intSocketState = -3;  // Start value

    btnConnectSocket->setText("Connect Socket");
    qDebug() << false;

    bool state = mySocket->doDisconnect();

    if (state) {
      intTunnelState = 0;  // no fault
      addTextToTextField("Disconnected TCP-Socket! Code: " +
                         QString::number(intTunnelState));
      addTextToTextField("");
    }

    if (!state) {
      intTunnelState = -1;  // any fault
      addTextToTextField("Problem disconnecting TCP-Socket! Code: " +
                         QString::number(intTunnelState));
    }
  }

  QApplication::setOverrideCursor(Qt::ArrowCursor);

  btnConnectSocket->setEnabled(true);
}

void Widget::btnSendPortScannerClicked(bool click) {
  qDebug() << "PushButton Port Scanner pushed: " << click;

  varTimeoutScanner = letScannerTimeout->text().toInt();
  qDebug() << "varTimeoutScanner" << varTimeoutScanner;

  this->setLineEditSocketDisable();
  this->setLineEditTunnelDisable();
  this->setLineEditScanPortDisable();
  this->setBottomButtonDisable();

  btnConnectSocket->setEnabled(false);
  btnConnectTunnel->setEnabled(false);
  btnPortScanner->setEnabled(false);

  addTextToTextField("Port scanning start");

  varScannerPortFrom = letScannerPortFrom->text().toInt();
  varScannerPortTo = letScannerPortTo->text().toInt();
  varTimeoutCommand = letScannerTimeout->text().toInt();

  QTcpSocket *iolanSocket = new QTcpSocket(this);

  if (click) {
    QApplication::setOverrideCursor(Qt::WaitCursor);

    QString strOpen = "", strClosed = "", strFailed = "";

    btnPortScanner->setText("Stop Scan");

    for (int i = varScannerPortFrom; i < varScannerPortTo + 1; i++) {
      strOpen = "";
      strClosed = "";

      iolanSocket->connectToHost(letScannerHost->text(), i,
                                 QIODevice::ReadWrite);

      if (iolanSocket->waitForConnected(varTimeoutScanner)) {
        qDebug() << "Connected:" << i;
        qDebug() << "Verbindung von meinem Router Port"
                 << iolanSocket->localPort() << "auf den Server Port"
                 << iolanSocket->peerPort();

        strOpen =
            "! " + QString::number(iolanSocket->peerPort()) + " port open";
        addTextToTextField(strOpen);

        qDebug() << iolanSocket->state();

        /*Enum von state() sind:
          UnconnectedState,
          HostLookupState,
          ConnectingState,
          ConnectedState,
          BoundState,
          ListeningState,
          ClosingState
         */

        iolanSocket->close();
      }

      else {
        qDebug() << "Failed: " << i;
        strClosed = "  " + QString::number(i) + " port blocked";
        addTextToTextField(strClosed);
      }
    }

    addTextToTextField("Port scanning finish");
    addTextToTextField("");

    iolanSocket->~QTcpSocket();
    btnPortScanner->setText("Start Scan");
    btnPortScanner->setChecked(false);
    btnPortScanner->setEnabled(true);
  }

  if (!click) {
    btnPortScanner->setText("Start Scan");

    qDebug() << iolanSocket->ConnectingState;

    this->setLineEditSocketEnable();
    this->setLineEditTunnelEnable();
    this->setLineEditScanPortEnable();
    this->setBottomButtonEnable();

    btnConnectSocket->setEnabled(true);
    btnConnectTunnel->setEnabled(true);
    btnPortScanner->setEnabled(true);
  }

  QApplication::setOverrideCursor(Qt::ArrowCursor);

  this->setLineEditSocketEnable();
  this->setLineEditTunnelEnable();
  this->setLineEditScanPortEnable();
  this->setBottomButtonEnable();

  btnConnectSocket->setEnabled(true);
  btnConnectTunnel->setEnabled(true);
  btnPortScanner->setEnabled(true);
}

void Widget::btnSendCommandClicked(bool click) {
  qDebug() << "btnSendCommandClicked" << click;
  qDebug() << btnSendCommand;
  qDebug() << "Status Tunnel Conection:" << intTunnelState;

  varTimeoutCommand = letCommandTimeout->text().toInt();
  qDebug() << "varTimeoutCommand" << varTimeoutCommand;

  QApplication::setOverrideCursor(Qt::WaitCursor);

  QString cmp = convertWildcardToCrtlSign(letCommandStartSign->text()) +
                convertWildcardToCrtlSign(letCommand->text()) +
                convertWildcardToCrtlSign(letCommandStopSign->text());

  if (intSocketState) {
    this->addTextToTextField(cmp);
    qDebug() << "cmp: " << cmp;

    ;
    QString tmp =
        mySocket->doWriteRead(cmp, varTimeoutCommand, rbtAscii->isChecked());
    qDebug() << "Answer Socket in Widget: " << tmp << "!";

    if (tmp == "") {
      tmp = "No answer from control!";
    }

    if (rbtHex->isChecked() && tmp.length() > 0 &&
        tmp != "No answer from control!") {
      tmp = inputSpaces(tmp);

      addTextToTextField("<- " + tmp + " -- hex received");

      tmp = convertHexStringAccordingComboBox(tmp);
      qDebug() << "String after convertion:" << tmp;
    } else {
      addTextToTextField("<- " + tmp);
    }
  }

  // according libssh2.h, V1.8.0 LIBSSH2_ERROR_KNOWN_HOSTS -46 is lowest fault
  // code!
  if (intTunnelState > -47 && (btnConnectTunnel->isChecked())) {
    this->addTextToTextField(cmp);
    qDebug() << "cmp: " << cmp;

    intTunnelState = myTunnel->direct_forwarding_send_reveive(
        cmp, varTimeoutCommand, rbtAscii->isChecked());
    QString tmp = myTunnel->getCommand();
    qDebug() << "Answer Tunnel in Widget: " << tmp << "!";

    if (tmp == "") {
      tmp = "No answer from control!";
    }

    if (rbtHex->isChecked() && tmp.length() > 0 &&
        tmp != "No answer from control!") {
      tmp = inputSpaces(tmp);

      addTextToTextField("<- " + tmp + " -- hex received");

      tmp = convertHexStringAccordingComboBox(tmp);
      qDebug() << "String after convertion:" << tmp;
    } else {
      addTextToTextField("<- " + tmp);
    }
  }

  QApplication::setOverrideCursor(Qt::ArrowCursor);
}

void Widget::btnSaveClicked(bool click) {
  qDebug() << "btnSaveClicked" << click;
  ;

  this->saveSettings();
}

void Widget::btnLoadClicked(bool click) {
  qDebug() << "btnLoadClicked" << click;

  this->loadSettings();
}

void Widget::btnExitClicked(bool click) {
  qDebug() << "btnExitClicked" << click;

  // Quit application
  QObject obj(nullptr);
  QObject::connect(&obj, &QObject::destroyed, QCoreApplication::instance(),
                   &QCoreApplication::quit);
}

void Widget::btnInfoSocketClicked(bool click) {
  qDebug() << "btnInfoClicked" << click;

  QString tmp = myTextInterface->getTextSocketInfo();
  tetTunnelQuery->setText(
      "INFO ABOUT TCP-SOCKET"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnInfoTunnelClicked(bool click) {
  qDebug() << "btnInfoTunnelClicked" << click;

  QString tmp = myTextInterface->getTextTunnelInfo();
  tetTunnelQuery->setText(
      "INFO ABOUT SSH-TUNNELING"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnInfoScannerClicked(bool click) {
  qDebug() << "btnInfoScannerClicked" << click;

  QString tmp = myTextInterface->getTextScannerInfo();
  tetTunnelQuery->setText(
      "INFO ABOUT PORT SCANNER"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnInfoCommandClicked(bool click) {
  qDebug() << "btnInfoCommandClicked" << click;

  QString tmp = myTextInterface->getTextCommandInfo();
  tetTunnelQuery->setText(
      "INFO ABOUT SUBMIT COMMANDS"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnInfoLicenseClicked(bool click) {
  qDebug() << "btnInfoLicenseClicked" << click;
  QString tmp = myTextInterface->getTextLicense();
  tetTunnelQuery->setText(
      "INFO ABOUT LICENSE & COPYRIGHT(C)"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnDeleteTxtEditClicked(bool click) {
  qDebug() << "btnDeleteTxtEditClicked" << click;

  tetTunnelQuery->clear();
}

void Widget::btnInfoEncryptionClicked(bool click) {
  qDebug() << "btnInfoEncryptionClicked" << click;

  QString tmp = myTextInterface->getTextEncyption();
  tetTunnelQuery->setText(
      "INFO ABOUT LICENSE & COPYRIGHT(C)"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnBugReportClicked(bool click) {
  qDebug() << "btnBugReportClicked" << click;

  Version *version = new Version();
  QString myVersion = version->getVersion();

  QDesktopServices::openUrl(
      QUrl("mailto:info@serial2net.ch?subject=Report bug"
           "&body=Herewith I report the following bug "
           "at the software ComTester " +
           myVersion + ":\r\n\r\n"));
}

void Widget::btnHelpClicked(bool click) {
  qDebug() << "btnHelpClicked" << click;

  QString tmp = myTextInterface->getTextHelp();
  tetTunnelQuery->setText(
      "INFO ABOUT LICENSE & COPYRIGHT(C)"
      "");
  tetTunnelQuery->setText(tmp);
}

void Widget::btnAboutClicked(bool click) {
  qDebug() << "btnAboutClicked" << click;

  AboutDialog *myAboutDialog = new AboutDialog();
  myAboutDialog->show();
}

void Widget::tabChanged(int tabIndex) {
  qDebug() << "tabCanged to: " << tabIndex;
  this->tabIndex = tabIndex;

  QPixmap pxpPictureSocket(":/resource/picSocket.png");
  QPixmap pxpPictureSsh(":/resource/picSsh.png");
  QPixmap pxpPictureScanner(":/resource/picScanner.png");

  if (tabIndex == 0) {
    lblPictureSchematic->setPixmap(pxpPictureSocket);
  }

  if (tabIndex == 1) {
    lblPictureSchematic->setPixmap(pxpPictureSsh);
  }

  if (tabIndex == 2) {
    lblPictureSchematic->setPixmap(pxpPictureScanner);
  }
}

void Widget::letCommandReturnPressed() {
  qDebug() << "Return pressed";

  emit btnSendCommandClicked(true);
}

void Widget::rbtAsciiClicked(bool click) {
  qDebug() << "rbtAsciiClicked" << click;

  if (click) {
    lblConvertHexTo->setEnabled(false);
    cboConvertHexTo->setEnabled(false);
  }
}

void Widget::rbtHexClicked(bool click) {
  qDebug() << "rbtHexClicked" << click;

  if (click) {
    lblConvertHexTo->setEnabled(true);
    cboConvertHexTo->setEnabled(true);
  }
}

void Widget::cboIndexChanged(int cboIndex) {
  qDebug() << "cboIndexChanged" << cboIndex;
}

QString Widget::inputSpaces(QString input) {
  QString output = "";
  int length = input.length();

  for (int i = 0; i < length; i++) {
    output = output + input[i];
    if (i > 0) {
      if (i % 2 > 0) {
        output = output + " ";
        // qDebug() << i;
      }
    }
  }

  return output;
}

QString Widget::convertHexStringToFloat(QString myAsciiCharString) {
  qDebug() << "Funktion: " << myAsciiCharString;
  myAsciiCharString = myAsciiCharString.replace(" ", "");
  qDebug() << "Funtion: " << myAsciiCharString;
  bool ok;
  int sign = 1;
  QByteArray array = myAsciiCharString.toLatin1();
  // QByteArray array("43480170");  // hex string for test functionality of this
  // methode. result should be 200.0056
  qDebug() << "Funtion: " << array;
  array = QByteArray::number(array.toLongLong(&ok, 16),
                             2);  // convert hex to binary -you don't need this
                                  // since your incoming data is binary
  if (array.length() == 32) {
    if (array.at(0) == '1') sign = -1;  // if bit 0 is 1 number is negative
    array.remove(0, 1);
    // remove sign bit
  }

  QByteArray fraction = array.right(23);  // get the fractional part
  double mantissa = 0;
  for (int i = 0; i < fraction.length(); i++)  // iterate through the array to
                                               // claculate the fraction as a
                                               // decimal.
    if (fraction.at(i) == '1') mantissa += 1.0 / (pow(2, i + 1));
  int exponent = array.left(array.length() - 23).toLongLong(&ok, 2) - 127;
  // claculate the exponentq
  QString answer =
      QString::number(sign * pow(2, exponent) * (mantissa + 1.0), 'f', 5);
  return answer;
}

QString Widget::convertHexStringToInteger(QString myAsciiCharString) {
  qDebug() << "convertHexStringToInteger" << myAsciiCharString;

  bool bStatus = false;
  // myAsciiCharString = "8E2"; // hex string for test functionality of this
  // methode. result should be 2274
  QString tmp = QString::number(myAsciiCharString.toInt(&bStatus, 16));
  return tmp;
}

QString Widget::convertHexStringToString(QString myAsciiCharString) {
  qDebug() << "convertHexStringToString" << myAsciiCharString;

  QByteArray text = QByteArray::fromHex("myAsciiCharString");
  // QByteArray text = QByteArray::fromHex("517420697320677265617421"); // hex
  // string for test functionality of this
  // methode. result should be "Qt is great!"
  QString tmp = text.data();
  return tmp;
}

QString Widget::convertHexStringAccordingComboBox(QString inputHex) {
  qDebug() << "convertHexStringAccordingComboBox" << inputHex;

  QString tmp = inputHex;

  int fromRight = (letNoBytesFromRight->text()).toInt() *
                  2;  // * 2 because a byte contains two hex signs

  if (tmp.length() != 0) {
    if (cboConvertHexTo->currentIndex() == 0) {  // no conversion
                                                 // do nothing
    }

    if (cboConvertHexTo->currentIndex() == 1) {  // convert to float
      tmp = inputHex.replace(" ", "");
      tmp = tmp.right(fromRight);
      addTextToTextField("<- " + tmp + " -- hex data");
      tmp = convertHexStringToFloat(tmp);
      addTextToTextField("<- " + tmp + " -- float");
    }

    if (cboConvertHexTo->currentIndex() == 2) {  // convert to integer
      tmp = inputHex.replace(" ", "");
      tmp = tmp.right(fromRight);

      addTextToTextField("<- " + tmp + " -- hex data");
      tmp = convertHexStringToInteger(tmp);
      addTextToTextField("<- " + tmp + " -- integer");
    }

    if (cboConvertHexTo->currentIndex() == 3) {  // convert to string
      tmp = inputHex.replace(" ", "");
      tmp = tmp.right(fromRight);

      addTextToTextField("<- " + tmp + " -- hex data");
      tmp = convertHexStringToString(tmp);
      addTextToTextField("<- " + tmp + " -- string");
    }
    qDebug() << "String after convert to" << cboConvertHexTo->currentIndex()
             << ":" << tmp;
  }

  return tmp;
}

bool Widget::convertStringToBool(QString inputString) {
  bool returnVal = false;

  if (inputString == "0") {
    returnVal = false;
  }
  if (inputString == "1") {
    returnVal = true;
  }

  return returnVal;
}

void Widget::loadSettingStartUp() {
  qDebug() << "loadSettings";
  qDebug() << "fileName: " << settings->fileName();
  qDebug() << "Setting isWritable: " << settings->isWritable();
  qDebug() << "Pfad: " << strPath;
  qDebug() << "Filename: " << strName;

  this->SshHost = settings->value("SshHost", "").toString();
  this->SshPort = settings->value("Sshport", "").toString();
  this->SshUser = settings->value("SshUser", "").toString();
  this->SshPassword = settings->value("SshPassword", "").toString();
  this->TunnelServer= settings->value("TunnelHost", "").toString();
  this->TunnelClient = settings->value("TunnelClient", "").toString();
  this->TunnelClientPort = settings->value("TunnelClientPort", "").toString();
  this->TunnelServerPort = settings->value("TunnelServerPort", "").toString();
  this->TunnelTimeout = settings->value("TunnelTimeout", "").toString();
  this->SocketHost = settings->value("SocketHost", "").toString();
  this->SocketPort = settings->value("SocketPort", "").toString();
  this->SocketTimeout = settings->value("SocketTimeout", "").toString();
  this->Command = settings->value("Command", "").toString();
  this->CommandStartSign = settings->value("CommandStartSign", "").toString();
  this->CommandStopSign = settings->value("CommandStopSign", "").toString();
  this->CommandDelimiter = settings->value("CommandDelimiter", "").toString();
  this->CommandTimeout = settings->value("CommandTimeout", "").toString();
  this->CommandIsAscii = settings->value("CommandIsAscii", "").toString();
  this->CommandIsHex = settings->value("CommandIsHex", "").toString();
  this->CommandConvertHexTo =
      settings->value("CommandConvertHexTo", "").toString();
  this->CommandBytesFromRight =
      settings->value("CommandBytesFromRight", "").toString();
  this->ScannerHost = settings->value("ScannerHost", "").toString();
  this->ScannerPortFrom = settings->value("ScannerPortFrom", "").toString();
  this->ScannerPortTo = settings->value("ScannerPortTo", "").toString();
  this->ScannerTimeout = settings->value("ScannerTimeout", "").toString();

  settings->sync();
}

void Widget::loadSettings() {
  // write local variabels into local ItemWidgets
  letSshHost->setText(SshHost);
  letSshPort->setText(SshPort);
  letSshUser->setText(SshUser);
  letSshPassword->setText(SshPassword);
  letTunnelHost->setText(TunnelServer);
  letTunnelClient->setText(TunnelClient);
  letTunnelClientPort->setText(TunnelClientPort);
  letTunnelServerPort->setText(TunnelServerPort);
  letTunnelTimeout->setText(TunnelTimeout);
  letSocketHost->setText(SocketHost);
  letSocketPort->setText(SocketPort);
  letSocketTimeout->setText(SocketTimeout);
  letCommand->setText(Command);
  letCommandStartSign->setText(CommandStartSign);
  letCommandStopSign->setText(CommandStopSign);
  letCommandDelimiter->setText(CommandDelimiter);
  letCommandTimeout->setText(CommandTimeout);
  rbtAscii->setChecked(convertStringToBool(CommandIsAscii));
  rbtHex->setChecked(convertStringToBool(CommandIsHex));
  cboConvertHexTo->setCurrentText(CommandConvertHexTo);
  letNoBytesFromRight->setText(CommandBytesFromRight);
  letScannerHost->setText(ScannerHost);
  letScannerPortFrom->setText(ScannerPortFrom);
  letScannerPortTo->setText(ScannerPortTo);
  letScannerTimeout->setText(ScannerTimeout);
}

void Widget::saveSettings() {
  qDebug() << "saveSettings";
  qDebug() << "fileName: " << settings->fileName();
  qDebug() << "Setting isWritable: " << settings->isWritable();
  qDebug() << "Pfad: " << strPath;
  qDebug() << "Filename: " << strName;

  // write into local variabels from ItemWidget
  SshHost = letSshHost->text();
  SshPort = letSshPort->text();
  SshUser = letSshUser->text();
  SshPassword = letSshPassword->text();
  TunnelServer = letTunnelHost->text();
  TunnelClient = letTunnelClient->text();
  TunnelClientPort = letTunnelClientPort->text();
  TunnelServerPort = letTunnelServerPort->text();
  TunnelTimeout = letTunnelTimeout->text();
  SocketHost = letSocketHost->text();
  SocketPort = letSocketPort->text();
  SocketTimeout = letSocketTimeout->text();
  Command = letCommand->text();
  CommandStartSign = letCommandStartSign->text();
  CommandStopSign = letCommandStopSign->text();
  CommandDelimiter = letCommandDelimiter->text();
  CommandTimeout = letCommandTimeout->text();
  CommandIsAscii = QString::number(rbtAscii->isChecked());
  CommandIsHex = QString::number(rbtHex->isChecked());
  CommandConvertHexTo = cboConvertHexTo->currentText();
  CommandBytesFromRight = letNoBytesFromRight->text();
  ScannerHost = letScannerHost->text();
  ScannerPortFrom = letScannerPortFrom->text();
  ScannerPortTo = letScannerPortTo->text();
  ScannerTimeout = letScannerTimeout->text();

  // write into lokal variables from setting file
  settings->setValue("SshHost", SshHost);
  settings->setValue("SshPort", SshPort);
  settings->setValue("SshUser", SshUser);
  settings->setValue("SshPassword", SshPassword);
  settings->setValue("TunnelHost", TunnelServer);
  settings->setValue("TunnelClient", TunnelClient);
  settings->setValue("TunnelClientPort", TunnelClientPort);
  settings->setValue("TunnelServerPort", TunnelServerPort);
  settings->setValue("TunnelTimeout", TunnelTimeout);
  settings->setValue("SocketHost", SocketHost);
  settings->setValue("SocketPort", SocketPort);
  settings->setValue("SocketTimeout", SocketTimeout);
  settings->setValue("Command", Command);
  settings->setValue("CommandStartSign", CommandStartSign);
  settings->setValue("CommandStopSign", CommandStopSign);
  settings->setValue("CommandDelimiter", CommandDelimiter);
  settings->setValue("CommandTimeout", CommandTimeout);
  settings->setValue("CommandIsAscii", CommandIsAscii);
  settings->setValue("CommandIsHex", CommandIsHex);
  settings->setValue("CommandConvertHexTo", CommandConvertHexTo);
  settings->setValue("CommandBytesFromRight", CommandBytesFromRight);
  settings->setValue("ScannerHost", ScannerHost);
  settings->setValue("ScannerPortFrom", ScannerPortFrom);
  settings->setValue("ScannerPortTo", ScannerPortTo);
  settings->setValue("ScannerTimeout", ScannerTimeout);

  // set RadioButtons

  // set ComboBox

  settings->sync();
}

Widget::~Widget() {}
