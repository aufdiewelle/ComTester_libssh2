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

#ifndef SSHTUNNEL_H
#define SSHTUNNEL_H

#include <include/libssh2.h>

#include <QString>
#include <QTcpSocket>

class sshtunnel {
 public:
  sshtunnel(int varTimeoutTunnel, int varTimeoutCommand);
  int getTunnelData(int sshPort, char *sshHost,
                    char *sshUser, char *sshPassword,
                    char *tunnelClient, int tunnelClientPort,
                    char *tunnelServer, int tunnelServerPort);
  int doConnectDisconnectTunnel(bool stateBtnConnectTunnel,
                                int varTimeoutTunnel);
  int direct_forwarding_send_reveive(QString strCommand, int varTimeoutCommand,
                                     bool isAscii);
  QString getCommand();

 private:
  QTcpSocket *myTcpSocket;
  LIBSSH2_SESSION *session;
  int rc;
  LIBSSH2_CHANNEL *channel;
  int sshPort = -1;
  const char *sshHost = "";
  const char *sshUser = "";
  const char *sshPassword = "";
  const char *tunnelClient = "";
  int tunnelClientPort = -1;
  const char *tunnelServer = "";
  int tunnelServerPort = -1;
  QString strCommand = "";
  QString strCommandReturn = "";
  char *chrCommand;
  bool stateBtnConnectTunnel = false;
  bool stateBtnConnectSocket = false;
  int varTimeoutTunnel;
  int varTimeoutCommand;
};

#endif  // SSHTUNNEL_H
