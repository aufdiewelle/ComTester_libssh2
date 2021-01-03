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

#include <QByteArray>
#include <QChar>
#include <QCoreApplication>
#include <QDebug>
#include <QString>
#include <QThread>
#include <sstream>

#include "sshtunnel.h"

sshtunnel::sshtunnel(int varTimeoutTunnel, int varTimeoutCommand) {
  this->varTimeoutTunnel = varTimeoutTunnel;
  qDebug() << "varTimeoutTunnel" << this->varTimeoutTunnel;
  this->varTimeoutCommand = varTimeoutCommand;
  qDebug() << "varTimeoutCommand" << this->varTimeoutCommand;
}

int sshtunnel::getTunnelData(int sshPort, char *sshHost,
                             char *sshUser, char *sshPassword,
                             char *tunnelClientHost, int tunnelClientPort,
                             char *tunnelServerHost, int tunnelServerPort) {
  this->sshPort = sshPort;
  this->sshHost = sshHost;
  this->sshUser = sshUser;
  this->sshPassword = sshPassword;
  this->tunnelClient = tunnelClientHost;
  this->tunnelClientPort = tunnelClientPort;
  this->tunnelServer = tunnelServerHost;
  this->tunnelServerPort = tunnelServerPort;

  qDebug() << this->sshPort;
  qDebug() << this->sshHost;
  qDebug() << this->sshUser;
  qDebug() << this->sshPassword;
  qDebug() << this->tunnelServer;
  qDebug() << this->tunnelClientPort;
  qDebug() << this->tunnelServerPort;

  return 0;
}

int sshtunnel::doConnectDisconnectTunnel(bool stateBtnConnectTunnel,
                                         int varTimeoutTunnel) {
  this->stateBtnConnectTunnel = stateBtnConnectTunnel;

  this->varTimeoutTunnel = varTimeoutTunnel;
  qDebug() << "varTimeoutTunnel" << this->varTimeoutTunnel;

  qDebug() << "enter doConnectDisconnectTunnel" << this->stateBtnConnectTunnel;

  if (stateBtnConnectTunnel) {
    rc = libssh2_init(0);
    if (rc) {
      qDebug("libssh2_init() error: %d", rc);
      return -1;
    }

    myTcpSocket = new QTcpSocket();
    myTcpSocket->connectToHost(sshHost, sshPort);
    if (!myTcpSocket->waitForConnected(varTimeoutTunnel)) {
      qDebug("Error connecting to host %s", sshHost);
      return -2;
    }
    /******************************************************************************/

    session = libssh2_session_init();
    if (!session) {
      qDebug("libssh2_session_init() failed");
      return -3;
    }
    /******************************************************************************/

    rc = libssh2_session_startup(session, myTcpSocket->socketDescriptor());
    if (rc) {
      qDebug("libssh2_session_startup() error: %d", rc);
      return -5;
    }
    /******************************************************************************/

    const char *fingerprint =
        libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);

    QByteArray array((char *)fingerprint);
    qDebug() << "Fingerprint: " << (QString(array.toHex()));

    qDebug("Password authentication: [%s] [%s]", sshUser, sshPassword);
    libssh2_userauth_list(session, sshUser, strlen(sshUser));
    // qDebug() << "libssh2_userauth_list: " << libssh2_userauth_list;

    if (rc) {
      qDebug("libssh2_session_startup() error: %d", rc);
      return -6;
    }
    /******************************************************************************/

    int state = libssh2_userauth_password(session, sshUser, sshPassword);

    if (state < 0) {
      qDebug("Password authentication failed");
      return -7;
    }

    /******************************************************************************/

    channel = NULL;
    channel = libssh2_channel_direct_tcpip_ex(
        session, tunnelServer, tunnelServerPort, tunnelClient, tunnelClientPort);

    int i = 0;
    int wait = 10;

    do {
      qDebug() << "Sleep 1s. /"
               << "Wait for" << wait - i << "s. more";
      QThread::sleep(1);

      // jump out of while after 10 sek
      i = i + 1;

    } while (channel == NULL && i < wait);

    if (channel == NULL) {
      return -8;
    }

    libssh2_session_set_blocking(session, 0);  // weil 1 default!

    return rc;
  }

  if (!stateBtnConnectTunnel) {
    myTcpSocket->disconnectFromHost();

    libssh2_session_disconnect(session, "Client disconnecting normally");
    rc = libssh2_session_free(session);
    libssh2_exit();

    return rc;
  }
}

QString sshtunnel::getCommand() {
  qDebug() << "getCommand: " << strCommandReturn;
  return strCommandReturn;
}

// SSH Com sen / receive****************************************************
int sshtunnel::direct_forwarding_send_reveive(QString strCommand,
                                              int varTimeoutCommand,
                                              bool isAscii) {
  int writenBytes = -1;
  int milliSecWrite = 0;
  int readBytes = -1;
  int milliSecRead = 0;

  this->varTimeoutCommand = varTimeoutCommand;
  qDebug() << "varTimeoutCommand" << this->varTimeoutCommand;

  QString temp = strCommand;

  // zum vom Tunnel lesen
  char bufferR[4096];

  // ASCII SSH Com**********************************************************
  if (isAscii) {
    // write read with ascii signs
    qDebug() << "Send signs codes in ASCII";

    QByteArray const bufferW(temp.toStdString().c_str());
    int arraylength = bufferW.count();

    qDebug() << "Submit data: " << temp << strlen(bufferW) << " : "
             << arraylength;
    int bufW = strlen(bufferW);

    // ASCII Schreiben auf Tunnel
    do {
      QThread::msleep(1);
      writenBytes = libssh2_channel_write(channel, bufferW, arraylength);
      milliSecWrite++;
    } while ((writenBytes < bufW) && (milliSecWrite < varTimeoutCommand));

    qDebug() << "Wait write " << QString::number(milliSecWrite) << " ms";

    if (milliSecWrite >= 50 && milliSecWrite < varTimeoutCommand) {
      qDebug()
          << "<---------------------ZEIT IST ZU HOCH--------------------->";
    } else if (milliSecWrite >= varTimeoutCommand) {
      qDebug()
          << "<---------------------FEHLER SCHREIBEN--------------------->";
    }

    qDebug() << "Length write:" << writenBytes;

    // ASCII Lesen vom Tunnel
    do {
      QThread::msleep(1);
      readBytes = libssh2_channel_read(channel, bufferR, sizeof(bufferR));
      milliSecRead++;
    } while ((readBytes < bufW) && (milliSecRead < varTimeoutCommand));

    qDebug() << "Wait read" << QString::number(milliSecRead) << " ms";

    if (milliSecRead >= 50 && milliSecRead < varTimeoutCommand) {
      qDebug()
          << "<---------------------ZEIT IST ZU HOCH--------------------->";
    } else if (milliSecRead >= varTimeoutCommand) {
      qDebug()
          << "<-----------------------FEHLER LESEN----------------------->";
    }

    qDebug() << "Length read:" << readBytes;
    strCommand = "";
    for (int i = 0; i < readBytes; i++) {
      strCommand = strCommand + bufferR[i];
    }

    qDebug() << "SSH ASCII empfangen: " << strCommand;
    strCommandReturn = strCommand;

  }

  // HEX SSH Com************************************************************
  else {
    // TODO: code for write read hex!
    // write read with ascii signs
    qDebug() << "Send signs codes in HEX";

    qDebug() << "temp  mit ' ': " << temp;
    temp = temp.replace(" ", "");
    qDebug() << "temp  ohne ' ': " << temp;

    QByteArray const bufferW = QByteArray::fromHex(temp.toLatin1());
    qDebug() << "bufferW:" << bufferW;

    int arraylength = bufferW.count();

    qDebug() << "Submit data: " << bufferW << strlen(bufferW) << " : "
             << arraylength;
    int bufW = strlen(bufferW);

    // HEX Schreiben auf Tunnel

    do {
      QThread::msleep(1);
      writenBytes = libssh2_channel_write(channel, bufferW, arraylength);
      milliSecWrite++;
    } while ((writenBytes < bufW) && (milliSecWrite < varTimeoutCommand));

    qDebug() << "Wait write " << QString::number(milliSecWrite) << " ms";

    if (milliSecWrite >= 50 && milliSecWrite < varTimeoutCommand) {
      qDebug()
          << "<---------------------ZEIT IST ZU HOCH--------------------->";
    } else if (milliSecWrite >= varTimeoutCommand) {
      qDebug()
          << "<---------------------FEHLER SCHREIBEN--------------------->";
    }

    qDebug() << "Length write:" << writenBytes;

    // HEX Lesen vom Tunnel

    do {
      QThread::msleep(1);
      readBytes = libssh2_channel_read(channel, bufferR, sizeof(bufferR));
      milliSecRead++;
    } while ((readBytes < bufW) && (milliSecRead < varTimeoutCommand));

    qDebug() << "Wait read" << QString::number(milliSecRead) << " ms";

    if (milliSecRead >= 50 && milliSecRead < varTimeoutCommand) {
      qDebug()
          << "<---------------------ZEIT IST ZU HOCH--------------------->";
    } else if (milliSecRead >= varTimeoutCommand) {
      qDebug()
          << "<-----------------------FEHLER LESEN----------------------->";
    }

    qDebug() << "Length read:" << readBytes;
    strCommand = "";
    QString temp;

    for (int i = 0; i < readBytes; i++) {
      temp = temp + bufferR[i];  // if not temp = temp + bu.. is used it will
                                 // not read ASCII values bigger then 127dec an
                                 // shows instead 0dec
      QChar c = temp.at(i);
      int asciiValDec = c.toLatin1();

      if (asciiValDec < 0) {
        asciiValDec = asciiValDec + 256;  // because c.toLatin1() ends at
                                          // 127dec, e.g. "£" = 211dec = d3hex
                                          // will return -45 and when -45dec +
                                          // 256dec = 211dec
      }

      QString stringHexVal;
      stringHexVal.setNum(asciiValDec, 16);

      if (stringHexVal.length() < 2) {
        stringHexVal.insert(0, QLatin1String("0"));
      }

      strCommand = strCommand + stringHexVal;

      qDebug() << "DEC:" << asciiValDec << "/HEX:" << stringHexVal;
    }

    qDebug() << "SSH HEX String: " << strCommand;

    strCommandReturn = strCommand;
  }

  return readBytes;
}
