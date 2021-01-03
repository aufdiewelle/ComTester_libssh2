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

#ifndef TEXTINTERFACE_H
#define TEXTINTERFACE_H

#include <QString>

class TextInterface
{
    public:
        TextInterface();
        QString getTextSocketInfo();
        QString getTextTunnelInfo();
        QString getTextScannerInfo();
        QString getTextCommandInfo();
        QString getTextLicense();
        QString getTextEncyption();
        QString getTextBugReport();
        QString getTextHelp();

    private:
        QString TextSocketInfo;
        QString TextTunnelInfo;
        QString TextScannerInfo;
        QString TextCommandInfo;
        QString TextLicense;
        QString TextEncyption;
        QString TextHelp;
};

#endif // TEXTINTERFACE_H
