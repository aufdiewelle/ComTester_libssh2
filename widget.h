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

#ifndef WIDGET_H
#define WIDGET_H

#include "sshtunnel.h"
#include "tcpsocket.h"
#include "textinterface.h"

#include <QWidget>
class QComboBox;
class QPushButton;
class QRadioButton;
class QLabel;
class QLineEdit;
class QTextEdit;
class QTabWidget;
class QPixmap;
class QSettings;

class Widget : public QWidget {
  Q_OBJECT

 public:
  Widget(QWidget *parent = 0);
  QString addTextToTextField(QString additionalText);
  QString convertWildcardToCrtlSign(QString data);
  QString convertCrtlSignToWildcard(QString data);
  void setLineEditTunnelDisable();
  void setLineEditTunnelEnable();
  void setLineEditSocketDisable();
  void setLineEditSocketEnable();
  void setLineEditScanPortDisable();
  void setLineEditScanPortEnable();
  void setLineEditCommandDisable();
  void setLineEditCommandEnable();
  void setBottomButtonDisable();
  void setBottomButtonEnable();
  QString inputSpaces(QString input);
  QString convertHexStringToFloat(QString myAsciiCharString);
  QString convertHexStringToInteger(QString myAsciiCharString);
  QString convertHexStringToString(QString myAsciiCharString);
  QString convertHexStringAccordingComboBox(QString inputHex);
  bool convertStringToBool(QString inputString);
  void loadSettingStartUp();
  void loadSettings();
  void saveSettings();
  ~Widget();

 private:
  sshtunnel *myTunnel;
  int intTunnelState = -3;
  tcpsocket *mySocket;
  bool intSocketState = false;
  QString strState = "";
  int tabIndex = -1;
  TextInterface *myTextInterface;

  QString strPath;
  QSettings *settings;
  QString strName;

  QString settingFilePath = "";
  QString SshHost = "";
  QString SshPort = "";
  QString SshUser = "";
  QString SshPassword = "";
  QString TunnelServer = "";
  QString TunnelServerPort = "";
  QString TunnelClient = "";
  QString TunnelClientPort = "";
  QString TunnelTimeout = "";
  QString SocketHost = "";
  QString SocketPort = "";
  QString SocketTimeout = "";
  QString Command = "";
  QString CommandStartSign = "";
  QString CommandStopSign = "";
  QString CommandDelimiter = "";
  QString CommandTimeout = "";
  QString CommandIsAscii = "";
  QString CommandIsHex = "";
  QString CommandConvertHexTo = "";
  QString CommandBytesFromRight = "";
  QString ScannerHost = "";
  QString ScannerPortFrom = "";
  QString ScannerPortTo = "";
  QString ScannerTimeout = "";

  QTabWidget *tabWidget;

  QWidget *widSocket;
  QWidget *widSSH;
  QWidget *widCMD;
  QWidget *widPort;
  QWidget *widBottomLine;

  QPushButton *btnConnectTunnel;
  QPushButton *btnConnectSocket;
  QPushButton *btnPortScanner;
  QPushButton *btnSendCommand;
  QPushButton *btnSave;
  QPushButton *btnLoad;
  QPushButton *btnExit;
  QPushButton *btnInfoSocket;
  QPushButton *btnInfoTunnel;
  QPushButton *btnInfoScanner;
  QPushButton *btnInfoCommand;
  QPushButton *btnInfoLicense;
  QPushButton *btnDeleteTxtEdit;
  QPushButton *btnInfoEncryption;
  QPushButton *btnBugReport;
  QPushButton *btnHelp;
  QPushButton *btnAbout;

  QRadioButton *rbtAscii;
  QRadioButton *rbtHex;

  QComboBox *cboConvertHexTo;

  QLabel *lblLicense;
  QLabel *lblSshTitel;
  QLabel *lblSshHost;
  QLabel *lblSshPort;
  QLabel *lblSshUser;
  QLabel *lblSshPassword;
  QLabel *lblTunnelTitel;
  QLabel *lblTunnelHost;
  QLabel *lblTunnelClient;
  QLabel *lblTunnelClientPort;
  QLabel *lblTunnelServerPort;
  QLabel *lblTunnelTimeout;
  QLabel *lblSocketTitel;
  QLabel *lblSocketHost;
  QLabel *lblSocketPort;
  QLabel *lblSocketTimeout;
  QLabel *lblCommandTitel;
  QLabel *lblSignCode;
  QLabel *lblCommand;
  QLabel *lblConvertHexTo;
  QLabel *lblNoBytesFromRight;
  QLabel *lblCommandStartSign;
  QLabel *lblCommandStopSign;
  QLabel *lblCommandDelimiter;
  QLabel *lblCommandTimeout;
  QLabel *lblPictureSchematic;
  QLabel *lblScannerTitel;
  QLabel *lblScannerHost;
  QLabel *lblScannerPortFrom;
  QLabel *lblScannerPortTo;
  QLabel *lblScannerTimeout;
  QLabel *lblScannerRemarks;
  QLabel *lblInfoEncryption;
  QLabel *lblBugReport;
  QLabel *lblHelp;
  QLabel *lblAbout;

  QLineEdit *letSshHost;
  QLineEdit *letSshPort;
  QLineEdit *letSshUser;
  QLineEdit *letSshPassword;
  QLineEdit *letTunnelHost;
  QLineEdit *letTunnelClient;
  QLineEdit *letTunnelClientPort;
  QLineEdit *letTunnelServerPort;
  QLineEdit *letTunnelTimeout;
  QLineEdit *letSocketHost;
  QLineEdit *letSocketPort;
  QLineEdit *letSocketTimeout;
  QLineEdit *letCommand;
  QLineEdit *letNoBytesFromRight;
  QLineEdit *letCommandStartSign;
  QLineEdit *letCommandStopSign;
  QLineEdit *letCommandDelimiter;
  QLineEdit *letCommandTimeout;
  QLineEdit *letScannerHost;
  QLineEdit *letScannerPortFrom;
  QLineEdit *letScannerPortTo;
  QLineEdit *letScannerTimeout;

  QTextEdit *tetTunnelQuery;

  //SSH
  int varSshPort = -1;
  char *varSshHost;
  QByteArray baSshHost;
  char *varSshUser;
  QByteArray baSshUser;
  char *varSshPassword;
  QByteArray baSshPassword;

  int varTunnelServerPort = -1; //IOLAN 10002
  char *varTunnelServer; //IOLAN 192.168.0.2 new
  QByteArray baTunnelServer; //IOLAN 192.168.0.2 new

  int varTunnelClientPort = -1; //10000 localhost
  char *varTunnelClient; //localhost
  QByteArray baTunnelClient; //localhost

  //TCP-IP
  char *varSocketHost; //TCP-IP
  QByteArray baSocketHost; //TCP-IP
  int varSocketPort = -1; //TCP-IP

  //Scanner
  int varScannerPortFrom = -1;
  int varScannerPortTo = -1;
  int varTimeoutTunnel = -1;
  int varTimeoutSocket = -1;
  int varTimeoutCommand = -1;
  int varTimeoutScanner = -1;

 private slots:
  void btnConnectTunnelClicked(bool click);
  void btnConnectSocketClicked(bool click);
  void btnSendPortScannerClicked(bool click);
  void btnSendCommandClicked(bool click);
  void btnSaveClicked(bool click);
  void btnLoadClicked(bool click);
  void btnExitClicked(bool click);
  void btnInfoSocketClicked(bool click);
  void btnInfoTunnelClicked(bool click);
  void btnInfoScannerClicked(bool click);
  void btnInfoCommandClicked(bool click);
  void btnInfoLicenseClicked(bool click);
  void btnDeleteTxtEditClicked(bool click);
  void btnInfoEncryptionClicked(bool click);
  void btnBugReportClicked(bool click);
  void btnHelpClicked(bool click);
  void btnAboutClicked(bool click);
  void tabChanged(int tabIndex);
  void letCommandReturnPressed();
  void rbtAsciiClicked(bool click);
  void rbtHexClicked(bool click);
  void cboIndexChanged(int cboIndex);
};

#endif  // WIDGET_H
