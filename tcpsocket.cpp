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

#include "tcpsocket.h"
#include <QDebug>

tcpsocket::tcpsocket(int varTimeoutSocket, int varTimeoutCommand) {
  iolanSocket = new QTcpSocket();
  this->varTimeoutSocket = varTimeoutSocket;
  this->varTimeoutCommand = varTimeoutCommand;
}

bool tcpsocket::doConnect(QString host, int port, int varTimeoutCommand) {
  this->varTimeoutSocket = varTimeoutCommand;
  qDebug() << "varTimeoutSocket" << varTimeoutSocket;

  iolanSocket->connectToHost(host, port, QIODevice::ReadWrite);

  if (iolanSocket->waitForConnected(varTimeoutSocket)) {
    qDebug() << "Connected!";
    return true;
  } else {
    qDebug() << "Not connected!";
    return false;
  }
}

QString tcpsocket::doWriteRead(QString var, int varTimeoutCommand,
                               bool isAscii) {
  this->varTimeoutCommand = varTimeoutCommand;
  qDebug() << "varTimeoutCommand" << varTimeoutCommand;

  if (isAscii) {
    QByteArray array(var.toStdString().c_str());

    // send
    qDebug() << "Send: " << array;
    iolanSocket->write(array);
    iolanSocket->waitForBytesWritten(varTimeoutCommand);
    iolanSocket->waitForReadyRead(varTimeoutCommand);

    qDebug() << "Number of Reading ASCII signs: "
             << iolanSocket->bytesAvailable();

    // get the data
    var = iolanSocket->readAll();

  } else {
    var = var.replace(" ", "");
    QByteArray array = QByteArray::fromHex(var.toLatin1());
    qDebug() << "QString convert into QByteAray and shown as HEX: "
             << array.toHex();

    // send
    qDebug() << "Send: " << array;
    iolanSocket->write(array);
    iolanSocket->waitForBytesWritten(varTimeoutCommand);
    iolanSocket->waitForReadyRead(varTimeoutCommand);

    qDebug() << "Number of Reading ASCII signs: "
             << iolanSocket->bytesAvailable();

    // get the data
    array = iolanSocket->readAll();
    var = QString(array.toHex());
  }

  return var;
}

bool tcpsocket::doDisconnect() {
  // close the connection
  iolanSocket->close();
  return true;
}
